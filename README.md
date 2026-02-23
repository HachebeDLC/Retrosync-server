# NeoSync Server (Self-Hosted)

This is a local Python implementation of the NeoSync backend services (Auth, Sync API, Notifications).

## Setup

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Server:**
    ```bash
    python3 main.py
    ```
    The server will start on `http://0.0.0.0:8000`.

## Configuration

*   **Storage:** Files are stored in the `storage/` directory.
*   **Database:** Currently uses a mock in-memory database (reset on restart).
*   **Quota:** Hardcoded to 10GB.

## Patched APK

To use this server with NeoStation, you must use the `neostation_patched.apk` which has been modified to point to your local IP (`192.168.1.32:8000`).

**Note:** The patched APK is **unsigned**. You must sign it before installing on Android (unless using an emulator/device that allows unsigned APKs or via adb install -r -t if applicable).
