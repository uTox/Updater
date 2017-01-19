#include <stdint.h>
#include <stdio.h>

#ifndef _WIN32_IE
#define _WIN32_IE 0x0800
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600

#include "utils.h"
#include "resource.h"

#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <shlobj.h>
#include <process.h>
#include <shlwapi.h>
#include <versionhelpers.h>

#include <stdint.h>
#include <sodium.h>

#define UPDATER_REVISION 5
#define CURRENT_VERSION 0x0B01

#define NUMBER_UPDATE_HOSTS 4
static const char *host_list[NUMBER_UPDATE_HOSTS] = {
    "download.utox.io",
    "downloads.utox.io",
    "version.utox.io",
    "173.242.118.202"
};


// UPDATER / RUNNER DOWNLOADS
#define UPDATER_VERSION  "runner_version"
#define UPDATER_STABLE   "runner_stable"
#define UPDATER_FILENAME "uTox_updater.exe"

#define TOX_VERSION_NAME_MAX_LEN 32


// uTox.exe defines
#define UTOX_TITLE "uTox"
#define TOX_EXE_NAME "uTox.exe"
#define UTOX_VERSION_STABLE "utox_version_stable"
#define UTOX_VERSION_DEVEL  "utox_version_devel"
static char download_target[] = "win32-latest";

#define TOX_UNINSTALL_FILENAME "uninstall.bat"
#define TOX_UNINSTALL_CONTENTS "cd %~dp0\n" UPDATER_FILENAME " --uninstall\nIF NOT EXIST uTox.exe del "\
                               "utox_runner.exe\nIF NOT EXIST uTox.exe del uninstall.bat & exit\nexit\n"

static const uint8_t TOX_SELF_PUBLIC_KEY[crypto_sign_ed25519_PUBLICKEYBYTES] = {
    0x64, 0x3B, 0xF6, 0xEF, 0x40, 0xAF, 0x61, 0x94, 0x79, 0x64, 0xDD, 0x41, 0x3D, 0x41, 0xC7, 0x3C,
    0xDE, 0xA3, 0x66, 0xD1, 0x7E, 0x3C, 0x6C, 0x49, 0x1D, 0xD4, 0x8F, 0x8F, 0x4B, 0xFD, 0xFF, 0xC8
};


static char tox_version_name[TOX_VERSION_NAME_MAX_LEN];

static char tox_updater_path[MAX_PATH];
static uint32_t tox_updater_path_len;

static bool is_tox_installed;
static bool is_tox_set_start_on_boot;

// Called arguments
PSTR my_cmd_args;
HINSTANCE my_hinstance;

// Common UI
static HWND main_window;
static HWND progressbar;
static HWND status_label;

void set_download_progress(int progress) {
    if (progressbar) {
        PostMessage(progressbar, PBM_SETPOS, progress, 0);
    }
}

void set_current_status(char *status) {
    SetWindowText(status_label, status);
}

static void init_tox_version_name() {
    FILE *version_file = fopen(TOX_EXE_NAME, "rb");
    if (version_file) {
        is_tox_installed = 1;
        fclose(version_file);
    }
}

#define UTOX_UPDATER_PARAM " --skip-updater"
#define UTOX_SET_START_ON_BOOT_PARAM " --set=start-on-boot"

static HANDLE utox_mutex;

static void open_utox_and_exit() {
    LOG_TO_FILE("Open and exit\n");
    char str[strlen(my_cmd_args) + sizeof(UTOX_UPDATER_PARAM) + sizeof(UTOX_SET_START_ON_BOOT_PARAM)];
    strcpy(str, my_cmd_args);
    strcat(str, UTOX_UPDATER_PARAM);

    if (is_tox_set_start_on_boot) {
        strcat(str, UTOX_SET_START_ON_BOOT_PARAM);
    }

    CloseHandle(utox_mutex);
    ShellExecute(NULL, "open", TOX_EXE_NAME, str, NULL, SW_SHOW);

    fclose(LOG_FILE);
    exit(0);
}

static void restart_updater() {
    CloseHandle(utox_mutex);
    ShellExecute(NULL, "open", tox_updater_path, my_cmd_args, NULL, SW_SHOW);

    fclose(LOG_FILE);
    exit(0);
}

static char* download_new_updater(uint32_t *new_updater_len) {
    for (int i = 0; i < NUMBER_UPDATE_HOSTS; ++i ) {
        char *new_updater = download_from_host(1, host_list[i], UPDATER_STABLE,
                                               strlen(UPDATER_STABLE), new_updater_len,
                                               TOX_SELF_PUBLIC_KEY);
        if (new_updater) {
            return new_updater;
        }
    }

    return NULL;
}

static bool install_new_updater(void *new_updater_data, uint32_t new_updater_data_len) {
    char new_path[MAX_PATH] = {0};
    FILE *file;

    memcpy(new_path, tox_updater_path, tox_updater_path_len);
    strcat(new_path, ".old");

    DeleteFile(new_path);
    MoveFile(tox_updater_path, new_path);

    file = fopen(tox_updater_path, "wb");
    if (!file) {
        LOG_TO_FILE("failed to write new updater");
        return 0;
    }

    fwrite(new_updater_data, 1, new_updater_data_len, file);

    fclose(file);
    return 1;
}

/* return 0 on success.
 * return -1 if could not write file.
 * return -2 if download failed.
 */
static int download_and_install_new_utox_version() {
    FILE *file;
    void *new_version_data;
    uint32_t len, rlen;

    for (int i = 0; i < NUMBER_UPDATE_HOSTS; ++i ) {
        new_version_data = download_from_host(0, host_list[i], download_target,
                                              strlen(download_target), &len, TOX_SELF_PUBLIC_KEY);

        if (new_version_data) {
            break;
        }
    }

    if (!new_version_data) {
        LOG_TO_FILE("download failed\n");
        if (is_tox_installed) {
            open_utox_and_exit();
        }

        return -2;
    }

    LOG_TO_FILE("Inflated size: %u\n", len);

    /* delete old version if found */
    file = fopen(UTOX_VERSION_STABLE, "rb");
    if (file) {
        char old_name[32];
        rlen = fread(old_name, 1, sizeof(old_name) - 1, file);
        old_name[rlen] = 0;

        /* Only there for smooth update from old updater. */
        DeleteFile(old_name);
        fclose(file);
    }

    /* write file */
    file = fopen(TOX_EXE_NAME, "wb");
    if (!file) {
        LOG_TO_FILE("fopen failed\n");
        free(new_version_data);
        return -1;
    }

    rlen = fwrite(new_version_data +4, 1, len-4, file);
    fclose(file);
    free(new_version_data);
    if (rlen != (len -4)) {
        LOG_TO_FILE("write failed (%u)\n", rlen);
        return -1;
    }

    return 0;
}

static int verify_runner() {
    FILE *file;
    char *new_version_data = NULL;
    uint32_t len = 0;

    for (int i = 0; i < NUMBER_UPDATE_HOSTS; ++i) {
        new_version_data = download_from_host(0, host_list[i], UPDATER_VERSION, strlen(UPDATER_VERSION),
                                              &len, TOX_SELF_PUBLIC_KEY);
        if (new_version_data) {
            break;
        }
    }

    if (!new_version_data) {
        LOG_TO_FILE("version download failed\n");
        return -1;
    }

    if (len != 8) {
        LOG_TO_FILE("invalid version length (%u)\n", len);
        free(new_version_data);
        LOG_TO_FILE("Time [%2X%2X%2X%2X]\n",
                    new_version_data[0], new_version_data[1],
                    new_version_data[2], new_version_data[3]);
        LOG_TO_FILE("Data [%2X%2X%2X%2X]\n",
                    new_version_data[4], new_version_data[5],
                    new_version_data[6], new_version_data[7]);
        return -1;
    }

    uint32_t ver = 0;
    memcpy(&ver, new_version_data + 4, 4);
    ver = ntohl(ver);
    LOG_TO_FILE("Runner current version %u, runner server version %u\n", UPDATER_REVISION, ver);


    if (ver > UPDATER_REVISION) {
        LOG_TO_FILE("new updater version available (%u)\n", ver);

        char *new_updater_data;
        uint32_t new_updater_data_len;

        new_updater_data = download_new_updater(&new_updater_data_len);

        if (!new_updater_data) {
            LOG_TO_FILE("self update download failed\n");
        } else {
            if (install_new_updater(new_updater_data, new_updater_data_len)) {
                LOG_TO_FILE("successful self update\n");
                free(new_version_data);
                restart_updater();
            }
        }
    }

    free(new_version_data);
    return 1;
}

static int verify_utox(void) {
    uint8_t *utox_version = NULL;
    size_t len = 0;
    for (int i = 0; i < NUMBER_UPDATE_HOSTS; ++i) {
        utox_version = download_from_host(0, host_list[i], UTOX_VERSION_STABLE, strlen(UTOX_VERSION_STABLE),
                                          &len, TOX_SELF_PUBLIC_KEY);
        if (utox_version) {
            break;
        }
    }

    if (!utox_version) {
        LOG_TO_FILE("version download failed\n");
        return -1;
    }

    if (len != 8) {
        LOG_TO_FILE("invalid version length (%u)\n", len);
        free(utox_version);
        LOG_TO_FILE("Time [%2X%2X%2X%2X]\n",
                    utox_version[0], utox_version[1],
                    utox_version[2], utox_version[3]);
        LOG_TO_FILE("Data [%2X%2X%2X%2X]\n",
                    utox_version[4], utox_version[5],
                    utox_version[6], utox_version[7]);
        return -1;
    }

    uint32_t ver = 0;
    memcpy(&ver, utox_version + 4, 4);
    ver = ntohl(ver);
    LOG_TO_FILE("Current ver %u\n", ver);

    if (ver > CURRENT_VERSION) {
        LOG_TO_FILE("New version of uTox available (%u -> %u)\n", CURRENT_VERSION, ver);

        char *new_updater_data;
        uint32_t new_updater_data_len;

        new_updater_data = download_new_updater(&new_updater_data_len);

        if (!new_updater_data) {
            LOG_TO_FILE("self update download failed\n");
        } else {
            if (install_new_updater(new_updater_data, new_updater_data_len)) {
                LOG_TO_FILE("successful self update\n");
                free(utox_version);
                restart_updater();
            }
        }
    } else {
        LOG_TO_FILE("No new uTox available (%u -> %u)\n", CURRENT_VERSION, ver);
    }

    return ver;
}

static int write_uninstall() {
    FILE *file = fopen(TOX_UNINSTALL_FILENAME, "wb");

    if (!file) {
        return -1;
    }

    int len = fwrite(TOX_UNINSTALL_CONTENTS, 1, sizeof(TOX_UNINSTALL_CONTENTS) - 1, file);

    fclose(file);
    if (len != sizeof(TOX_UNINSTALL_CONTENTS) - 1) {
        return -1;
    }

    return 0;
}

/* return 0 on success.
 * return -1 if could not write file.
 * return -2 if download failed.
 */
static int install_tox(int create_desktop_shortcut,
                       int create_startmenu_shortcut,
                       int use_with_tox_url,
                       wchar_t *install_path,
                       int install_path_len )
{
    char dir[MAX_PATH];

    wchar_t selfpath[MAX_PATH];
    GetModuleFileNameW(my_hinstance, selfpath, MAX_PATH);

    SHCreateDirectoryExW(NULL, install_path, NULL);
    SetCurrentDirectoryW(install_path);
    if (CopyFileW(selfpath, L""UPDATER_FILENAME, 0) == 0) {
        LOG_TO_FILE("Unable to copy %S to %s\n", selfpath, UPDATER_FILENAME);
        return -1;
    }

    int ret = write_uninstall();
    if (ret) {
        LOG_TO_FILE("Unable write the uninstall script\n");
        return ret;
    }

    set_current_status("downloading and installing tox...");

    ret = download_and_install_new_utox_version();
    if (ret) {
        LOG_TO_FILE("Unable download and install\n");
        return ret;
    }

    HRESULT hr;
    HKEY key;

    if (create_desktop_shortcut || create_startmenu_shortcut) {
        hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        if (SUCCEEDED(hr)) {
            //start menu
            IShellLink* psl;

            // Get a pointer to the IShellLink interface. It is assumed that CoInitialize
            // has already been called.
            hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLink, (LPVOID*)&psl);
            if (SUCCEEDED(hr)) {
                IPersistFile* ppf;

                // Set the path to the shortcut target and add the description.

                GetCurrentDirectory(MAX_PATH, dir);
                psl->lpVtbl->SetWorkingDirectory(psl, dir);
                strcat(dir, "\\"TOX_EXE_NAME);
                psl->lpVtbl->SetPath(psl, dir);
                psl->lpVtbl->SetDescription(psl, "Tox");

                // Query IShellLink for the IPersistFile interface, used for saving the
                // shortcut in persistent storage.
                hr = psl->lpVtbl->QueryInterface(psl, &IID_IPersistFile, (LPVOID*)&ppf);

                if (SUCCEEDED(hr)) {
                    wchar_t wsz[MAX_PATH + 64];
                    if (create_startmenu_shortcut) {
                        hr = SHGetFolderPathW(NULL, CSIDL_STARTMENU, NULL, 0, wsz);
                        if (SUCCEEDED(hr)) {
                            LOG_TO_FILE("%ls\n", wsz);
                            wcscat(wsz, L"\\Programs\\Tox.lnk");
                            hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
                        }
                    }

                    if (create_desktop_shortcut) {
                        hr = SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, wsz);
                        if (SUCCEEDED(hr)) {
                            wcscat(wsz, L"\\Tox.lnk");
                            hr = ppf->lpVtbl->Save(ppf, wsz, TRUE);
                        }
                    }

                    ppf->lpVtbl->Release(ppf);
                }
                psl->lpVtbl->Release(psl);
            }
        }
    }

    if (use_with_tox_url) {
        GetCurrentDirectory(MAX_PATH, dir);
        strcat(dir, "\\" TOX_EXE_NAME);

        char str[MAX_PATH];

        if (RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Classes\\tox", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
            LOG_TO_FILE("nice\n");
            RegSetValueEx(key, NULL, 0, REG_SZ, (BYTE*)"URL:Tox Protocol", sizeof("URL:Tox Protocol"));
            RegSetValueEx(key, "URL Protocol", 0, REG_SZ, (BYTE*)"", sizeof(""));

            HKEY key2;
            if (RegCreateKeyEx(key, "DefaultIcon", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                int i = sprintf(str, "%s,101", dir) + 1;
                RegSetValueEx(key2, NULL, 0, REG_SZ, (BYTE*)str, i);
            }

            if (RegCreateKeyEx(key, "shell", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                if (RegCreateKeyEx(key2, "open", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS) {
                    if (RegCreateKeyEx(key, "command", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key2, NULL) == ERROR_SUCCESS) {
                        int i = sprintf(str, "%s %%1", dir) + 1;
                        RegSetValueEx(key2, NULL, 0, REG_SZ, (BYTE*)str, i);
                    }
                }
            }
        }
    }

    if (RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\uTox", 0, NULL, 0,
                       KEY_ALL_ACCESS, NULL, &key, NULL) == ERROR_SUCCESS)
        {
            wchar_t icon[install_path_len + 64];
            wchar_t uninstall[install_path_len + 64];
            memcpy(icon, install_path, install_path_len * 2);
            icon[install_path_len] = 0;
            uninstall[0] = 0;
            wcscat(uninstall, L"cmd /C start \"\" /MIN \"");

            wcscat(icon, L"\\uTox.exe");
            wcscat(uninstall, install_path);
            wcscat(uninstall, L"\\uninstall.bat\"");

            RegSetValueEx(key, NULL, 0, REG_SZ, (BYTE*)"", sizeof(""));
            RegSetValueEx(key, "DisplayName", 0, REG_SZ, (BYTE*)"uTox", sizeof("uTox"));
            RegSetValueExW(key, L"InstallLocation", 0, REG_SZ, (BYTE*)install_path, wcslen(install_path) * 2);
            RegSetValueExW(key, L"DisplayIcon", 0, REG_SZ, (BYTE*)icon, wcslen(icon) * 2);
            RegSetValueExW(key, L"UninstallString", 0, REG_SZ, (BYTE*)uninstall, wcslen(uninstall) * 2);
    }
    return 0;
}

static int uninstall_tox() {
    if (MessageBox(NULL, "Are you sure you want to uninstall uTox?", "uTox Updater", MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES) {
        wchar_t wsz[MAX_PATH + 64];

        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_STARTMENU, NULL, 0, wsz))) {
            wcscat(wsz, L"\\Programs\\Tox.lnk");
            DeleteFileW(wsz);
        }

        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, wsz))) {
            wcscat(wsz, L"\\Tox.lnk");
            DeleteFileW(wsz);
        }

        SHDeleteKey(HKEY_CURRENT_USER, "Software\\Classes\\tox");
        SHDeleteKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\uTox");
        SHDeleteValue(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "uTox");
        DeleteFile(TOX_EXE_NAME);
        DeleteFile(UTOX_VERSION_STABLE);
        MessageBox(main_window, "uTox uninstalled.", "uTox Updater", MB_OK | MB_SETFOREGROUND);
    }

    exit(0);
}

#define UTOX_INSTALL_ENDED 18273

static void buttons_enable(bool enable) {
    Button_Enable(GetDlgItem(main_window, ID_INSTALL_BUTTON),               enable);
    Button_Enable(GetDlgItem(main_window, ID_BROWSE_BUTTON),                enable);
    Button_Enable(GetDlgItem(main_window, ID_DESKTOP_SHORTCUT_CHECKBOX),    enable);
    Button_Enable(GetDlgItem(main_window, ID_STARTMENU_SHORTCUT_CHECKBOX),  enable);
    Button_Enable(GetDlgItem(main_window, ID_TOX_URL_CHECKBOX),             enable);
}

static void start_installation() {
    HWND desktop_shortcut_checkbox = GetDlgItem(main_window, ID_DESKTOP_SHORTCUT_CHECKBOX);
    HWND startmenu_shortcut_checkbox = GetDlgItem(main_window, ID_STARTMENU_SHORTCUT_CHECKBOX);
    HWND start_on_boot_checkbox = GetDlgItem(main_window, ID_START_ON_BOOT_CHECKBOX);
    HWND tox_url_checkbox = GetDlgItem(main_window, ID_TOX_URL_CHECKBOX);
    HWND browse_textbox = GetDlgItem(main_window, ID_BROWSE_TEXTBOX);

    bool create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url;

    wchar_t install_path[MAX_PATH];
    int install_path_len = GetWindowTextW(browse_textbox, install_path, MAX_PATH);

    if (install_path_len == 0) {
        MessageBox(main_window, "Please select a folder to install uTox in", "Error", MB_OK | MB_SETFOREGROUND);
        PostMessage(main_window, WM_APP, UTOX_INSTALL_ENDED, 0);
        return;
    }

    create_desktop_shortcut = Button_GetCheck(desktop_shortcut_checkbox);
    create_startmenu_shortcut = Button_GetCheck(startmenu_shortcut_checkbox);
    use_with_tox_url = Button_GetCheck(tox_url_checkbox);
    is_tox_set_start_on_boot = Button_GetCheck(start_on_boot_checkbox);

    LOG_TO_FILE("will install with options: %u %u %u %ls\n", create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url, install_path);

    if (MessageBox(main_window, "Are you sure you want to continue?", "uTox Updater", MB_YESNO | MB_SETFOREGROUND) != IDYES) {
        PostMessage(main_window, WM_APP, UTOX_INSTALL_ENDED, 0);
        return;
    }

    buttons_enable(0);
    int ret = install_tox(create_desktop_shortcut, create_startmenu_shortcut, use_with_tox_url, install_path, install_path_len);
    if (ret == 0) {
        set_current_status("installation complete");

        MessageBox(main_window, "Installation successful.", "uTox Updater", MB_OK | MB_SETFOREGROUND);
        open_utox_and_exit();
    } else if (ret == -1) {
        set_current_status("could not write to install directory.");
    } else if (ret == -2) {
        set_current_status("download error, please check your internet connection and try again.");
    } else {
        set_current_status("error during installation");

        MessageBox(main_window, "Installation failed. If it's not an internet issue please send the log file (tox_log.txt) to the developers.",
                                "uTox Updater", MB_OK | MB_SETFOREGROUND);
        exit(0);
    }

    PostMessage(main_window, WM_APP, UTOX_INSTALL_ENDED, 0);
    buttons_enable(1);
}

static void set_utox_path(wchar_t *path) {
    HWND browse_textbox = GetDlgItem(main_window, ID_BROWSE_TEXTBOX);

    unsigned int str_len = wcslen(path);
    if (str_len != 0) {
        wchar_t file_path[str_len + sizeof(L"\\uTox")];
        memcpy(file_path, path, str_len * sizeof(wchar_t));
        memcpy(file_path + str_len, L"\\uTox", sizeof(L"\\uTox"));
        SetWindowTextW(browse_textbox, file_path);
    }
}

static void browse_for_install_folder() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    IFileOpenDialog *pFileOpen;
    hr = CoCreateInstance(&CLSID_FileOpenDialog, NULL, CLSCTX_ALL, &IID_IFileOpenDialog, (void*)&pFileOpen);
    if (SUCCEEDED(hr)) {
        hr = pFileOpen->lpVtbl->SetOptions(pFileOpen, FOS_PICKFOLDERS);
        hr = pFileOpen->lpVtbl->SetTitle(pFileOpen, L"Tox Install Location");
        hr = pFileOpen->lpVtbl->Show(pFileOpen, NULL);

        if (SUCCEEDED(hr)) {
            IShellItem *pItem;
            hr = pFileOpen->lpVtbl->GetResult(pFileOpen, &pItem);

            if (SUCCEEDED(hr)) {
                PWSTR pszFilePath;
                hr = pItem->lpVtbl->GetDisplayName(pItem, SIGDN_FILESYSPATH, &pszFilePath);

                if (SUCCEEDED(hr)) {
                    set_utox_path(pszFilePath);
                    CoTaskMemFree(pszFilePath);
                }
                pItem->lpVtbl->Release(pItem);
            }
        }
        pFileOpen->lpVtbl->Release(pFileOpen);

        CoUninitialize();
    } else {
        wchar_t path[MAX_PATH];
        BROWSEINFOW bi = {
            .pszDisplayName = path,
            .lpszTitle = L"Install Location",
            .ulFlags = BIF_USENEWUI | BIF_NONEWFOLDERBUTTON,
        };
        LPITEMIDLIST lpItem = SHBrowseForFolderW(&bi);
        if (!lpItem) {
            return;
        }

        SHGetPathFromIDListW(lpItem, path);
        set_utox_path(path);
    }
}

static void check_updates() {
    set_current_status("Fetching updater version...");

    int runner_ver = verify_runner();
    set_download_progress(0);

    if (runner_ver == -1) {
        LOG_TO_FILE("Unable to verify runner\n");
        if (!is_tox_installed) {
            exit(2);
            MessageBox(main_window, "Error fetching latest version data. Please check your internet connection.\n\nExiting now...",
                                    "Error", MB_OK | MB_SETFOREGROUND);
        } else {
            open_utox_and_exit();
        }
    }

    int utox_ver = verify_utox();

    set_current_status("version data fetched successfully");
    Button_Enable(GetDlgItem(main_window, ID_INSTALL_BUTTON), 1);

    if (is_tox_installed) {
        if (utox_ver > CURRENT_VERSION) {
            ShowWindow(main_window, SW_SHOW);
            set_current_status("found new version");

            if (MessageBox(NULL, "A new version of uTox is available.\nUpdate?", "uTox Updater",
                MB_YESNO | MB_ICONQUESTION | MB_SETFOREGROUND) == IDYES)
                {
                    download_and_install_new_utox_version();
            }
        }

        open_utox_and_exit();
    }
}

INT_PTR CALLBACK MainDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);

    static bool install_thread_running = 0;

    switch (message) {
            case WM_INITDIALOG: {
                return (INT_PTR)TRUE;
            }
            case WM_CLOSE: {
                PostQuitMessage(0);
                break;
            }
            case WM_COMMAND: {
                if (HIWORD(wParam) == BN_CLICKED) {
                    switch (LOWORD(wParam)) {
                        case ID_CANCEL_BUTTON: {
                            if (MessageBox(main_window, "Are you sure you want to exit?", "uTox Updater", MB_YESNO | MB_SETFOREGROUND) == IDYES) {
                                if (is_tox_installed) {
                                    open_utox_and_exit();
                                }
                                else {
                                    exit(0);
                                }
                            }
                            break;
                        }

                        case ID_INSTALL_BUTTON: {
                            if (!install_thread_running) {
                                if (_beginthread(start_installation, 0, 0) != -1) {
                                    install_thread_running = 1;
                                }
                            }

                            break;
                        }
                        case ID_BROWSE_BUTTON: {
                            buttons_enable(0);
                            browse_for_install_folder();
                            buttons_enable(1);

                            break;
                        }
                    }
                }
                break;
            }

            case WM_APP: {
                if (wParam == UTOX_INSTALL_ENDED)
                    install_thread_running = 0;
            }
    }

    return (INT_PTR)FALSE;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmd, int nCmdShow) {
    if ((utox_mutex = CreateMutex(NULL, 0, UTOX_TITLE))) {
        DWORD err = GetLastError();
        if (err == ERROR_ALREADY_EXISTS || err == ERROR_ACCESS_DENIED) {
            /* uTox is running. */
            HWND window = FindWindow(UTOX_TITLE, NULL);
            if (window) {
                SetForegroundWindow(window);
            }
            return 0;
        }
    } else {
        exit(1); // Failed to create mutex
    }


    my_cmd_args = cmd;
    my_hinstance = hInstance;

    tox_updater_path_len = GetModuleFileName(NULL, tox_updater_path, MAX_PATH);
    tox_updater_path[tox_updater_path_len] = 0;

    char path[MAX_PATH], *s;
    memcpy(path, tox_updater_path, tox_updater_path_len + 1);
    s = path + tox_updater_path_len;
    while (*s != '\\') {
        s--;
    }

    *s = 0;
    SetCurrentDirectory(path);

    init_tox_version_name();

    uint32_t cmdln_ver = 0;
    /* Convert PSTR command line args from windows to argc */
    int argc = 0;
    LPWSTR *arglist = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (NULL != arglist) {
        for (int i = 0; i < argc; i++) {
            if (wcscmp(arglist[i], L"--uninstall") == 0) {
                if (is_tox_installed) {
                    uninstall_tox();
                    return 0;
                }
            } else if (wcscmp(arglist[i], L"--version") == 0) {
                LOG_TO_FILE("Got version ");
                if (argc > (i + 1)) {
                    cmdln_ver = wcstol(arglist[i + 1], NULL, 10);
                    LOG_TO_FILE("it is %u ", cmdln_ver);
                }
                LOG_TO_FILE("\n");
            }
        }
    }

    LOG_FILE = fopen("tox_log.txt", "w");

    /* initialize winsock */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        LOG_TO_FILE("WSAStartup failed\n");
        return 1;
    }

    if (IsWindowsVistaOrGreater()) {
        /* check if we are on a 64-bit system */
        bool iswow64 = 0;
        bool (WINAPI *fnIsWow64Process)(HANDLE, bool*)  = (void*)GetProcAddress(GetModuleHandleA(TEXT("kernel32")),"IsWow64Process");
        if (fnIsWow64Process) {
            LOG_TO_FILE("Asking for x64\n");
            fnIsWow64Process(GetCurrentProcess(), &iswow64);
        }

        if (iswow64) {
            /* replace the arch in the download_target/tox_version_name strings (todo: not use constants for offsets) */
            download_target[3] = '6';
            download_target[4] = '4';
            tox_version_name[0] = '6';
            tox_version_name[1] = '4';
            LOG_TO_FILE("detected 64bit system\n");
        } else {
            download_target[3] = '3';
            download_target[4] = '2';
            tox_version_name[0] = '3';
            tox_version_name[1] = '2';
            LOG_TO_FILE("detected 32bit system\n");
        }
    } else {
        download_target[3] = 'x';
        download_target[4] = 'p';
        tox_version_name[0] = 'x';
        tox_version_name[1] = 'p';
        LOG_TO_FILE("detected XP system\n");
    }

    /* init common controls */
    INITCOMMONCONTROLSEX InitCtrlEx;

    InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
    InitCtrlEx.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&InitCtrlEx);

    main_window = CreateDialog(my_hinstance, MAKEINTRESOURCE(IDD_MAIN_DIALOG), NULL, MainDialogProc);

    if (!main_window) {
        LOG_TO_FILE("error creating main window %lu\n", GetLastError());
        exit(0);
    }

    progressbar = GetDlgItem(main_window, ID_PROGRESSBAR);
    set_download_progress(0);
    status_label = GetDlgItem(main_window, IDC_STATUS_LABEL);

    if (!is_tox_installed) {
        // show installer controls
        HWND desktop_shortcut_checkbox = GetDlgItem(main_window, ID_DESKTOP_SHORTCUT_CHECKBOX);
        Button_SetCheck(desktop_shortcut_checkbox, 1);
        ShowWindow(desktop_shortcut_checkbox, SW_SHOW);

        HWND startmenu_shortcut_checkbox = GetDlgItem(main_window, ID_STARTMENU_SHORTCUT_CHECKBOX);
        Button_SetCheck(startmenu_shortcut_checkbox, 1);
        ShowWindow(startmenu_shortcut_checkbox, SW_SHOW);

        HWND start_on_boot_checkbox = GetDlgItem(main_window, ID_START_ON_BOOT_CHECKBOX);
        Button_SetCheck(start_on_boot_checkbox, 1);
        ShowWindow(start_on_boot_checkbox, SW_SHOW);

        ShowWindow(GetDlgItem(main_window, ID_TOX_URL_CHECKBOX), SW_SHOW);

        wchar_t appdatalocal_path[MAX_PATH] = {0};
        if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdatalocal_path) == S_OK) {
            set_utox_path(appdatalocal_path);
        }

        Button_Enable(GetDlgItem(main_window, ID_INSTALL_BUTTON), 0);
        ShowWindow(GetDlgItem(main_window, ID_INSTALL_BUTTON), SW_SHOW);

        Edit_SetReadOnly(GetDlgItem(main_window, ID_BROWSE_TEXTBOX), 1);
        ShowWindow(GetDlgItem(main_window, ID_BROWSE_TEXTBOX), SW_SHOW);
        ShowWindow(GetDlgItem(main_window, ID_BROWSE_BUTTON), SW_SHOW);
        ShowWindow(GetDlgItem(main_window, IDC_INSTALL_FOLDER_LABEL), SW_SHOW);
        ShowWindow(main_window, SW_SHOW);
    }

    _beginthread(check_updates, 0, NULL);

    MSG msg;

    while (GetMessage(&msg, NULL, 0, 0) > 0) {
        DispatchMessage(&msg);
    }

    open_utox_and_exit();

    return 0;
}
