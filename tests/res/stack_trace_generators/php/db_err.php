<?php
// pdo_failure.php

function connect(): PDO {
    // Intentionally bogus DSN
    $dsn = "mysql:host=127.0.0.1;port=9999;dbname=does_not_exist;charset=utf8mb4";
    $user = "invalid_user";
    $pass = "invalid_pass";

    // PDO will throw PDOException on failure when ERRMODE_EXCEPTION is set.
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    return $pdo;
}

function main(): void {
    $pdo = connect();
    echo "Connected!\n";
}

main();

