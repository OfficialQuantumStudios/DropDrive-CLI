# DropDrive CLI Client

A command-line interface for the DropDrive file sharing platform. This tool allows you to upload, manage, and delete files from the command line.

## Installation

1. Make sure you have Python 3.6+ installed
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic Commands

```bash
# Upload a file anonymously
python3 dropdrive-client.py upload /path/to/file.txt

# Upload a file to your user account (requires login)
python3 dropdrive-client.py upload /path/to/file.txt --user

# Login to your account
python3 dropdrive-client.py login your_login_id your_password

# List your uploaded files
python3 dropdrive-client.py listfiles

# Delete a file
python3 dropdrive-client.py delete file_id_here

# Logout
python3 dropdrive-client.py logout
```

### Configuration

The CLI client stores authentication information in `~/.dropdrive_config.json`. This file contains:
- Authentication token
- User ID
- Login ID

## Commands

### `upload <file_path> [--user]`

Upload a file to DropDrive.

- `file_path`: Path to the file you want to upload
- `--user`: Upload as an authenticated user (requires login first)

**Examples:**
```bash
# Anonymous upload
python3 dropdrive-client.py upload document.pdf

# User upload (requires login)
python3 dropdrive-client.py upload document.pdf --user
```

### `login <login_id> <password>`

Login to your DropDrive account.

- `login_id`: Your DropDrive login ID
- `password`: Password (which is same as ID)

**Example:**
```bash
python3 dropdrive-client.py login your_login_id your_password
```

### `logout`

Logout from DropDrive and clear stored credentials.

**Example:**
```bash
python3 dropdrive-client.py logout
```

### `delete <file_id>`

Delete a file from your account. You must be logged in and own the file.

- `file_id`: The ID of the file to delete

**Example:**
```bash
python3 dropdrive-client.py delete abc123def456
```

### `listfiles`

List all files in your account. You must be logged in.

**Example:**
```bash
python3 dropdrive-client.py listfiles
```

## Features

- **Smart chunking**: Automatic optimal chunk sizes based on file size
- **Progress tracking**: See upload progress in real-time
- **Authentication**: Secure login with JWT tokens
- **User and anonymous uploads**: Upload files with or without an account
- **File management**: List and delete your uploaded files
- **Cross-platform**: Works on Windows, macOS, and Linux

## 2FA Support

If your account has 2FA enabled:
- Login will work normally
- File deletion requires 2FA via Web Interface
- Other operations work without additional verification

## Security Notes

- Authentication tokens are stored locally in `~/.dropdrive_config.json`
- Tokens expire after 24 hours
- Use `logout` to clear stored credentials
- For anonymous uploads, keep the owner token, so you can delete the files later.

## Troubleshooting

### "Must be logged in" errors
Make sure you've logged in first:
```bash
python3 dropdrive-client.py your_id your_password
```

### "File not found" errors
Check that the file path is correct and the file exists.

### 2FA errors
Some operations (like file deletion) may require 2FA verification through the web interface if you have 2FA enabled.

## Development

The CLI client is built with:
- Python 3.6+
- `wget` library for HTTP communications
- `argparse` for command-line interface
- `pathlib` for cross-platform file handling

I allow you to change the script however you want to, if you encounter bugs please report them on Discord or via Issues tab on GitHub.



