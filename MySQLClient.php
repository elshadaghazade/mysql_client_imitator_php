<?php

namespace MySQLClientImitator {

    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    
    
    class MySQLClient {

        private $client;
        private $userName;
        private $password;
        private $serverAddress;
        private $serverPort;
        private $connectionPhasePacket = null;

        public function __construct($serverAddress = "127.0.0.1", $serverPort = 3306, $userName = null, $password = null) {
            $this->userName = $userName;
            $this->password = $password;
            $this->serverAddress = $serverAddress;
            $this->serverPort = $serverPort;

            // connecting to the server and waiting handshake response
            $this->connect($serverAddress, $serverPort);

            // sending login request to the server
            $this->logIn();
        }

        // sending login request to the server
        private function logIn() {
            $packet = $this->getResponse();

            // if response is err_packet than throw an exception
            if ($packet instanceof ERR_PACKET) {
                throw new MySQLErrorException($packet);
            }

            // if server reponse is not excpecting connection_phase_packet than throws an exception
            if (!($packet instanceof CONNECTION_PHASE_PACKET)) {
                throw new \Exception("Connection phase packet error");
            }
            
            $this->connectionPhasePacket = $packet;

            // creates login_request_packet
            $packet = new LOGIN_REQUEST_PACKET($this->userName, $this->password, $packet);
            // get binary packet
            $request = $packet->getPacketBinary();
            
            // sending login request to the server
            stream_socket_sendto($this->client, $request);
            
            $response = $this->getResponse();
            
            // if a server returns OK_PACKET than we logged in to the mysql successfully
            if ($response instanceof OK_PACKET) {
                echo "You are welcome!\n\r";
                echo "Server version is " . $this->connectionPhasePacket->serverVersion . "\n\r";
                echo "You are connected as " . $this->userName . "@" . $this->serverAddress . ":" . $this->serverPort . "\n\r";
                echo "Your thread ID is " . $this->connectionPhasePacket->threadId . "\n\r";
            } else if($response instanceof ERR_PACKET) {
                throw new MySQLErrorException($response);
            } else {
                throw new \Exception("Unknown error");
            }
        }

        // returns packet object
        private function getResponse() {
            
            $response = stream_socket_recvfrom($this->client, 65536);
            $value = unpack('H*', $response);
            $response = $value[1];
            $packet = new MYSQL_PACKET($response);


            switch ($packet->getHeader()) {
                case OK_PACKET::HEADER:
                    return new OK_PACKET($response);
                case ERR_PACKET::HEADER:
                    return new ERR_PACKET($response);
                case EOF_PACKET::HEADER:
                    return new EOF_PACKET($response);
                default:
                    return new CONNECTION_PHASE_PACKET($response);
            }
        }

        // connects to the server
        private function connect($serverAddress, $serverPort) {
            $this->client = stream_socket_client("tcp://{$serverAddress}:{$serverPort}/root", $errno, $errorMessage, 1800, STREAM_CLIENT_CONNECT | STREAM_CLIENT_PERSISTENT);
            stream_set_blocking($this->client, true);
            stream_set_timeout($this->client, 1800);

            if ($this->client === false) {
                throw new Exception("Failed to connect: " . $errorMessage);
            }
        }

        public static function str2hex($string) {
            $hex = '';
            for ($i = 0; $i < strlen($string); $i++) {
                $ord = ord($string[$i]);
                $hexCode = dechex($ord);
                $hex .= substr('0' . $hexCode, -2);
            }
            return strToUpper($hex);
        }

        public static function hex2str($hex) {
            $str = null;
            for ($i = 0; $i < strlen($hex); $i+=2)
                $str .= chr(hexdec(substr($hex, $i, 2)));

            return $str;
        }

        public function __destruct() {
            fclose($this->client);
        }

    }

    class MYSQL_PACKET {

        public $response;

        public function __construct($response) {
            $this->response = $response;
        }

        public function getHeader() {
            return substr($this->response, 8, 2);
        }

        /*const SERVER_STATUS_IN_TRANS = 0x0001; // a transaction is active
        const SERVER_STATUS_AUTOCOMMIT = 0x0002; // auto-commit is enabled
        const SERVER_MORE_RESULTS_EXISTS = 0x0008;
        const SERVER_STATUS_NO_GOOD_INDEX_USED = 0x0010;
        const SERVER_STATUS_NO_INDEX_USED = 0x0020;
        const SERVER_STATUS_CURSOR_EXISTS = 0x0040; // Used by Binary Protocol Resultset to signal that COM_STMT_FETCH must be used to fetch the row-data.
        const SERVER_STATUS_LAST_ROW_SENT = 0x0080;
        const SERVER_STATUS_DB_DROPPED = 0x0100;
        const SERVER_STATUS_NO_BACKSLASH_ESCAPES = 0x0200;
        const SERVER_STATUS_METADATA_CHANGED = 0x0400;
        const SERVER_QUERY_WAS_SLOW = 0x0800;
        const SERVER_PS_OUT_PARAMS = 0x1000;
        const SERVER_STATUS_IN_TRANS_READONLY = 0x2000; // in a read-only transaction
        const SERVER_SESSION_STATE_CHANGED = 0x4000; // connection state information has changed*/
        
        
        public static function getFixedLengthInt($str, $startPos, $length) {
            return array(
                'start_position' => $startPos,
                'end_position' => $startPos + $length * 2,
                'value' => strrev(substr($str, $startPos, $length * 2))
            );
        }
        
        public static function getLenEncInt ($str, $startPos) {
            $firstByte = substr($str, $startPos, 2);
            $value = null;
            $endPos = 0;
            
            switch($firstByte) {
                case "fe": // 9 bytes length integer
                    $endPos += 9*2;
                    break;
                case "fd": // 4 bytes length integer
                    $endPos += 4*2;
                    break;
                case "fc": // 3 bytes length integer
                    $endPos += 3*2;
                    break;
                default: // 1 byte length integer
                    $endPos += 2;
            }
            
            return array(
                'start_position' => $startPos,
                'end_position' => $endPos + $startPos,
                'value' => strrev(substr($value, $startPos, $endPos))
            );
        }
        
        
        public static function getFixedLengthString ($str, $startPos, $length) {
            return array(
                'start_position' => $startPos,
                'end_position' => $startPos + $length * 2,
                'value' => substr($str, $startPos, $length * 2)
            );
        }
        
        public static function getNullTerminatedString ($str, $startPos) {
            $value = "";
            $endPos = 0;
            
            $str = substr($str, $startPos);
            
            $chunkedStr = preg_split("/[\s\t\n\r]+/", chunk_split($str, 2));
            foreach($chunkedStr as $key => $val) {
                $value .= $val;
                $endPos += 2;
                if($val == "00") {
                    break;
                }
            }
            
            return array(
                'start_position' => $startPos,
                'end_position' => $endPos + $startPos,
                'value' => $value
            );
            
        }
        
        public static function getLengthEncodedString($str, $startPos) {
            $length = self::getLenEncInt($str, $startPos);
            $endPos = hexdec($length['value']) * 2;
            $value = substr($str, $startPos + $length['end_position'], $endPos);
            return array(
                'start_position' => $startPos,
                'end_position' => $startPos + $length['end_position'] + $endPos,
                'value' => $value
            );
        }
        
        public static function getEOFString ($str, $startPos) {
            $value = substr($str, $startPos);
            
            return array(
                'start_position' => $startPos,
                'end_position' => $startPos + strlen($value),
                'value' => $value
            );
        }

    }

    class OK_PACKET extends MYSQL_PACKET {

        const HEADER = "00";
        
        public $packetLength;
        public $packetNumber;
        public $affectedRows;
        public $lastInsertId;
        public $statusFlag;
        public $warnings;
        public $info;

        public function __construct($response) {
            parent::__construct($response);

            $this->parseResponse();
        }

        public function parseResponse() {
            $this->packetLength = substr($this->response, 0, 6);
            $this->packetNumber = substr($this->response, 6, 2);
            $this->affectedRows = substr($this->response, 10, 2);
            $this->lastInsertId = substr($this->response, 12, 2);
            $this->statusFlag = substr($this->response, 14, 4);
            $this->info = substr($this->response, 18);
        }
    }

    class ERR_PACKET extends MYSQL_PACKET {

        const HEADER = "ff";

        public $packetLength;
        public $packetNumber;
        public $errorCode;
        public $sqlState;
        public $errorMessage;

        public function __construct($response) {
            parent::__construct($response);

            $this->parseResponse();
        }

        public function parseResponse() {
            $this->packetLength = substr($this->response, 0, 6);
            $this->packetNumber = substr($this->response, 6, 2);
            $this->errorCode = hexdec(substr($this->response, 10, 4));
            $this->sqlState = hexdec(substr($this->response, 16, 10));
            $this->errorMessage = MySQLClient::hex2str(substr($this->response, 26));
        }

    }

    class EOF_PACKET extends MYSQL_PACKET {

        const HEADER = "fe";

    }

    class CONNECTION_PHASE_PACKET extends MYSQL_PACKET {

        public $packetLength;
        public $packetNumber;
        public $protocol;
        public $serverVersion;
        public $threadId;
        private $salt1;
        private $salt2;
        public $salt;
        public $serverCapabilities;
        public $serverLanguage;
        public $serverStatus;
        public $unused;
        public $payload;

        public function __construct($response) {
            parent::__construct($response);

            $this->parseResponse();
        }

        public function parseResponse() {
            $res = self::getFixedLengthInt($this->response, 0, 3);
            $this->packetLength = $res['value'];
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 1);
            $this->packetNumber = $res['value'];
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 1);
            $this->protocol = $res['value'];
            
            $res = self::getNullTerminatedString($this->response, $res['end_position']);
            $this->serverVersion = MySQLClient::hex2str($res['value']);
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 4);
            $this->threadId = hexdec($res['value']);
            
            $res = self::getFixedLengthString($this->response, $res['end_position'], 8);
            $this->salt1 = $res['value'];
            
            // filler
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 1);
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 2);
            $this->serverCapabilities = $res['value'];
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 1);
            $this->serverLanguage = $res['value'];
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 2);
            $this->serverStatus = $res['value'];
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 2);
            $this->serverCapabilities .= $res['value'];
            
            $res = self::getFixedLengthInt($this->response, $res['end_position'], 1);
            $saltPart2Length = hexdec($res['value']) - 8;
            
            $res = self::getFixedLengthString($this->response, $res['end_position'], 10);
            $this->unused = $res['value'];
            
            $res = self::getNullTerminatedString($this->response, $res['end_position']);
            $this->salt2 = $res['value'];
            
            
            $res = self::getNullTerminatedString($this->response, $res['end_position']);
            $this->payload = $res['value'];

            $this->salt1 = trim(MySQLClient::hex2str($this->salt1));
            $this->salt2 = trim(MySQLClient::hex2str($this->salt2));

            $this->salt = $this->salt1 . $this->salt2;
        }

    }

    class LOGIN_REQUEST_PACKET extends MYSQL_PACKET {

        public $userName;
        public $password;
        public $packet;
        public $packetNumber;
        public $clientCapabilities;
        public $maxPacket;
        public $charset;
        public $unused;
        public $passwordLength;
        public $payload;

        public function __construct($userName, $password, CONNECTION_PHASE_PACKET $packet) {
            $this->packet = $packet;
            $this->userName = $userName;
            $this->password = $password;

            $this->preparePayload();
        }

        public static function encryptPassword($password, $salt) {
            return (sha1($password, true) ^ sha1($salt . sha1(sha1($password, true), true), true));
        }

        private function preparePayload() {
            $this->packetNumber = hex2bin("01"); // packet number is one
            $this->clientCapabilities = hex2bin("05a6");
            $this->extendedClientCapabilities = hex2bin("0f00");
            $this->maxPacket = hex2bin("00000001");
            $this->charset = hex2bin(dechex("33"));
            $this->unused = hex2bin("0000000000000000000000000000000000000000000000");
            $this->userName = hex2bin(MySQLClient::str2hex($this->userName) . "00");
            $this->password = self::encryptPassword($this->password, $this->packet->salt);
            $this->passwordLength = hex2bin(dechex(mb_strlen($this->password, '8bit')));
            $this->payload = hex2bin(MySQLClient::str2hex("mysql_native_password") . "00");
        }

        public function getPacketBinary() {
            $packet = $this->clientCapabilities;
            $packet .= $this->extendedClientCapabilities;
            $packet .= $this->maxPacket;
            $packet .= $this->charset;
            $packet .= $this->unused;
            $packet .= $this->userName;
            $packet .= $this->passwordLength;
            $packet .= $this->password;
            $packet .= $this->payload;


            $packetLength = hex2bin(dechex(mb_strlen($packet, '8bit')) . "0000");
            return $packetLength . $this->packetNumber . $packet;
        }

    }

    class MySQLErrorException extends \Exception {

        public function __construct(ERR_PACKET $packet = null, $errorCode = null) {
            if ($packet == null) {
                parent::__construct("Unknown Error", 0);
            } else {
                parent::__construct($packet->errorMessage . ". Sql State - " . $packet->sqlState, $packet->errorCode);
            }
        }

    }

}