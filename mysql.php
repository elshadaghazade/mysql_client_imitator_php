<?php

include "MySQLClient.php";

use MySQLClientImitator\MySQLClient as MySQLClient;
use MySQLClientImitator\MySQLErrorException as MySQLErrorException;

if($argc < 3) {
    echo "There is insufficient argument count\n\r";
    exit;
}

$host = null;
$port = null;
$userName = null;
$password = null;

for($i = 1; $i < $argc; $i++) {
    $startsWith = substr($argv[$i], 0, 2);
    $value = substr($argv[$i], 2);
    
    if(!trim($value)) {
        continue;
    }
    
    if($startsWith == "-u") {
        $userName = $value;
    } else if($startsWith == "-p") {
        $password = $value;
    } else if($startsWith == "-h") {
        $splittedValue = preg_split("/:/", $value);
        $host = $splittedValue[0];
        $port = $splittedValue[1];
    }
}

try {
    $client = new MySQLClient($host, $port, $userName, $password);
} catch (MySQLErrorException $e) {
    echo $e->getMessage() . "\n\r";
}