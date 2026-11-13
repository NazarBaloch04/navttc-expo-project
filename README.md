# Ransomware Behavior Monitor

A native Windows C++17 desktop demonstration for observing file activity in a folder explicitly selected by the user. It records file events in SQLite, applies simple behavior-based heuristics, and includes a safe disposable-file simulator.

## Features

- Dark Win32 dashboard with Dashboard, Live Monitoring, Threat Detection, Security Alerts, Event Logs, Analytics, Settings, and About pages.
- Recursive monitoring of the selected folder using `ReadDirectoryChangesW`; monitoring runs on a worker thread and can be stopped from the UI.
- SQLite persistence for file events, heuristic scores, reviewed alerts, and detection thresholds.
- Detection indicators for rapid modifications, repeated renames, deletions, repeated extension changes, high-frequency operations, and combinations of indicators.
- Risk scores and low/medium/high categories are heuristics, not proof of infection.
- Search and severity filters, alert review, and CSV event export.
- Event Logs searches the latest 5,000 records in memory; CSV export reads the SQLite history.
- A safe simulation folder under `%LOCALAPPDATA%\RansomwareBehaviorMonitor\simulation`. Demo events are labeled and use harmless text files; deletion and cleanup require confirmation and are restricted to `rbm_demo_*` files in that folder.
- No administrator privileges are required for normal use.

## Requirements

- Windows 10 or 11.
- Visual Studio 2022 Build Tools (Desktop development with C++) or a Visual Studio installation with the C++ workload.
- CMake 3.21 or newer.
- SQLite runtime: the application first looks for Windows' `winsqlite3.dll`, then `sqlite3.dll`. If neither is available, place a trusted `sqlite3.dll` matching the application's architecture beside the executable.

No Python packages or third-party UI framework are required.

## Build in VS Code

1. Install Visual Studio 2022 Build Tools and select **Desktop development with C++**.
2. Install CMake and the VS Code **CMake Tools** extension.
3. Open this project folder in VS Code. If prompted, select a Visual Studio 2022 x64 kit.
4. Configure and build:

   ```powershell
   cmake -S . -B build -A x64
   cmake --build build --config Release
   ```

5. Launch:

   ```powershell
   .\build\Release\RansomwareBehaviorMonitor.exe
   ```

Alternatively, run the two CMake commands from a **Developer PowerShell for VS 2022** terminal.

## Use the application

1. Open **Live Monitoring** and choose one existing folder.
2. Click **Start monitoring**. Only the selected folder and its subfolders are watched.
3. Review new activity in Dashboard, Security Alerts, or Event Logs. Use **Stop** before changing the monitored folder.
4. Use **Export CSV** on Event Logs to save matching records.
5. To demonstrate detection without touching personal files, open Live Monitoring and use the Safe Simulation Lab. All simulated records are labeled. Delete and cleanup actions display a confirmation prompt.
6. Adjust the rolling 10-second detection thresholds on Settings.

The SQLite database is stored at `%LOCALAPPDATA%\RansomwareBehaviorMonitor\monitoring.db`. Safe simulation files are stored separately in the `simulation` subfolder.

## Scope notes

- The application does not encrypt files, execute malware, terminate processes, or claim a device is infected.
- The dashboard and analytics use recorded data only; simulated activity is visibly labeled.
- The standalone build exports event-history CSV files. PDF report generation and date-range report selection are not included.
- Monitoring events are historical records; stopping monitoring does not delete them.
