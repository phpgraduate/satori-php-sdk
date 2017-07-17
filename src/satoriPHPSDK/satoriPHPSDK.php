<?php
namespace satoriPHPSDK;

use Evenement\EventEmitter;
use React\EventLoop\LoopInterface;
use React\Socket\Connection;

class rtm extends EventEmitter
{
    const TOKEN_LENGHT = 16;
    const TYPE_ID_SUBSCRIBE = 3;
    const TYPE_ID_PUBLISH = 4;
    
    /**
     * @var string
     */
    private $key;
    
    /**
     * @var string
     */
    private $role;
    
    /**
     * @var string
     */
    private $roleSecretKey;

    /**
     * @var LoopInterface
     */
    private $loop;
    
    /**
     * @var int
     */
    private $protocol;
    
    /**
     * @var string
     */
    private $host;

    /**
     * @var int
     */
    private $port;

    /**
     * @var string
     */
    private $origin;

    /**
     * @var string
     */
    private $path;

    /**
     * @var Connection
     */
    private $socket;

    /**
     * @var bool
     */
    private $connected = false;

    /**
     * @var bool
     */
    private $authenticated = false;

    /**
     * 
     * @param LoopInterface $loop
     * @param string $host
     * @param int $port
     * @param string $path
     * @param null|string $origin
     */
    public function __construct($config, LoopInterface $loop)
    {
    	if ($config['endpoint']) {
    		$this->setProtocol('wss' === substr($config['endpoint'], 0, 3) ? 'tls' : 'tcp');    		
    		$this->setHost($this->getProtocol() === 'tls' ? substr($config['endpoint'], 6) : substr($config['endpoint'], 6));
    		$this->setPort($this->getProtocol() === 'tls' ? 443 : 80);
    	}
    	$this->setRole($config['role']);
    	$this->setRoleSecretKey($config['roleSecretKey']);
        $this->setLoop($loop);
        $this->setPath('/v2?appkey='.$config['appkey']);
        $this->setKey($this->generateToken(self::TOKEN_LENGHT));
        // Connect to client
        $this->connect();
    }

    /**
     * Connect client to server
     *
     * @throws ConnectionException
     * @return $this
     */
    public function connect()
    {
    	$root = $this;
    	
    	$client = @stream_socket_client("{$this->getProtocol()}://{$this->getHost()}:{$this->getPort()}");
    	if (!$client) {
    		throw new ConnectionException;
    	}
    	$this->setSocket(new Connection($client, $this->getLoop()));
    	
    	$this->getSocket()->write($this->createHeader());
    	$this->getSocket()->on('data', function ($data) use ($root) {
    		
    		if (!$this->connected) {
    			$this->connected = $root->checkConnection($data);
    		}
    		
    		if (!$this->authenticated && $this->connected) {
    			$this->authenticate($data);
    		} 
    		else 
    		{    		
    			$data = $this->hybi10Decode($data);
    			if ($data !== '') {
    				$arrData = json_decode($data, true);
    			    
    				switch ($arrData['action']) {
    					case 'rtm/subscription/data':
    						$this->emit('rtm/subscription/data', array($data, $this));
    						break;
    					case 'rtm/publish/ok':
    						$this->emit('rtm/publish/ok', array($data, $this));
    				}
    			}
    		}
    	});   	
    		
    	return $this;
    }
    
    /**
     * Parse raw incoming data
     *
     * @param $header
     * @return array
     */
    private function checkConnection($header)
    {    	
	    $retval = array();	    
	    $fields = explode("\r\n", preg_replace('/\x0D\x0A[\x09\x20]+/', ' ', $header));
	    foreach ($fields as $field) {
	    	if (preg_match('/([^:]+): (.+)/m', $field, $match)) {
	    		$match[1] = preg_replace_callback('/(?<=^|[\x09\x20\x2D])./', function ($matches) {
	    			return strtoupper($matches[0]);
	    		}, strtolower(trim($match[1])));
	    			if (isset($retval[$match[1]])) {
	    				$retval[$match[1]] = array($retval[$match[1]], $match[2]);
	    			} else {
	    				$retval[$match[1]] = trim($match[2]);
	    			}
	    	} else if (preg_match('!HTTP/1\.\d (\d)* .!', $field)) {
	    		$retval["status"] = $field;
	    	}
	    }
	    
	    if (isset($retval['Sec-Websocket-Accept'])) {
	    	if (base64_encode(pack('H*', sha1($this->key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'))) === $retval['Sec-Websocket-Accept']) {
	    		return true;
	    	}
	    }
	    
	    return false;
    }
    
    /**
     * Authenticate request
     *
     */
    private function authenticate($response) {
    	
    	$arrContent = json_decode($this->hybi10Decode($response), true);
    	switch ($arrContent['action']) {
    		case 'auth/handshake/ok':
    			$nonce = $arrContent['body']['data']['nonce'];
    			$hash = base64_encode(hash_hmac('md5', utf8_encode($nonce), utf8_encode($this->getRoleSecretKey()), true));
    			$this->sendData(array("action"=>"auth/authenticate","body"=>array("method"=>"role_secret","credentials"=>array("hash"=>$hash)),"id"=>2));
    			break;
    			
    		case 'auth/authenticate/ok':
    			$this->authenticated = true;
    			$this->emit('open', array($this));
    			break;
    			
    		default:
    			$this->sendData(array("action"=>"auth/handshake","body"=>array("method"=>"role_secret","data"=>array("role"=> $this->getRole())),"id"=>1));
    	}    	
    	
    }
       
    /**
     * Disconnect on destruct
     */
    function __destruct()
    {
        $this->disconnect();
    }

    /**
     * Disconnect from server
     */
    public function disconnect()
    {
        $this->connected = false;
        if ($this->socket instanceof Connection) {
            $this->socket->close();
        }
    }

    /**
     * @return bool
     */
    public function isConnected()
    {
        return $this->connected;
    }

    /**
     * @param string $topicUri
     * @param string $event
     */
    public function publish($topicUri, $event)
    {
        $this->sendData(array("action"=>"rtm/publish","body"=>array("channel"=>$topicUri,"message"=>$event),"id"=>self::TYPE_ID_PUBLISH));        
    }

    /**
     * @param string $topicUri
     */
    public function subscribe($topicUri)
    {
    	$this->sendData(array("action"=>"rtm/subscribe","body"=>array("channel"=>$topicUri,"fast_forward"=>true),"id"=>self::TYPE_ID_SUBSCRIBE));    	
    }

    /**
     * @param string $topicUri
     */
    public function unsubscribe($topicUri)
    {
        $this->sendData(array(
            self::TYPE_ID_UNSUBSCRIBE,
            $topicUri
        ));
    }

    
    /**
     * @param $data
     * @param $header
     */
    private function receiveData($data)
    {
        if (!$this->isConnected()) {
            $this->disconnect();
            return;
        }
		$arrContent = json_decode($data, true);
                
		if (!empty($arrContent)) {
			switch ($arrContent['id']) {
				case self::TYPE_ID_SUBSCRIBE:
					$this->onSubscribe($data);
					break;
            }
        }
    }

    function onSubscribe($data) {
    	echo $data;
    }
    /**
     * @param $data
     * @param string $type
     * @param bool $masked
     */
    private function sendData($data, $type = 'text', $masked = true)
    {
        if (!$this->isConnected()) {
            $this->disconnect();
            return;
        }
        echo "Send: " . json_encode($data) . "\r\n";
        $this->getSocket()->write($this->hybi10Encode(json_encode($data)));
    }
    
    /**
     * Create header for websocket client
     *
     * @return string
     */
    private function createHeader()
    {
        $host = $this->getHost();
        if ($host === '127.0.0.1' || $host === '0.0.0.0') {
            $host = 'localhost';
        }

        $origin = $this->getOrigin() ? $this->getOrigin() : "null";

        return
            "GET {$this->getPath()} HTTP/1.1" . "\r\n" .
            "Origin: {$origin}" . "\r\n" .
            "Host: {$host}:{$this->getPort()}" . "\r\n" .
            "Sec-WebSocket-Key: {$this->getKey()}" . "\r\n" .
            "User-Agent: Ratchet->Pawl/0.0.1\r\n" .
            "pragma: no-cache\r\n" .
            "cache-control: no-cache\r\n" .
            "Upgrade: websocket" . "\r\n" .
            "Connection: Upgrade" . "\r\n" .
            //"Sec-WebSocket-Protocol: wamp" . "\r\n" .
            "Sec-WebSocket-Version: 13" . "\r\n" . "\r\n";
    }

    

    /**
     * Generate token
     *
     * @param int $length
     * @return string
     */
    private function generateToken($length)
    {
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"?$%&/()=[]{}';

        $useChars = array();
        // select some random chars:
        for ($i = 0; $i < $length; $i++) {
            $useChars[] = $characters[mt_rand(0, strlen($characters) - 1)];
        }
        // Add numbers
        array_push($useChars, rand(0, 9), rand(0, 9), rand(0, 9));
        shuffle($useChars);
        $randomString = trim(implode('', $useChars));
        $randomString = substr($randomString, 0, self::TOKEN_LENGHT);

        return base64_encode($randomString);
    }

   
    /**
     * @param int $port
     * @return $this
     */
    public function setPort($port)
    {
        $this->port = (int)$port;
        return $this;
    }

    /**
     * @return int
     */
    public function getPort()
    {
        return $this->port;
    }

    /**
     * @param Connection $socket
     * @return $this
     */
    public function setSocket(Connection $socket)
    {
        $this->socket = $socket;
        return $this;
    }

    /**
     * @return Connection
     */
    public function getSocket()
    {
        return $this->socket;
    }

    /**
     * @param string $role
     */
    public function setRole($role)
    {
    	$this->role = $role;
    }
    
    /**
     * @return role
     */
    public function getRole()
    {
    	return $this->role;
    }
    
    /**
     * @param string $roleSecretKey
     */
    public function setRoleSecretKey($roleSecretKey)
    {
    	$this->roleSecretKey = $roleSecretKey;
    }
    
    /**
     * @return roleSecretKey
     */
    public function getRoleSecretKey()
    {
    	return $this->roleSecretKey;
    }
    
    /**
     * @param string $protocol
     */
    public function setProtocol($protocol)
    {
    	$this->protocol= $protocol;
    }
    
    /**
     * @return protocol
     */
    public function getProtocol()
    {
    	return $this->protocol;
    }
    
    /**
     * @param string $host
     * @return $this
     */
    public function setHost($host)
    {
        $this->host = (string)$host;
        return $this;
    }

    /**
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * @param null|string $origin
     */
    public function setOrigin($origin)
    {
        if (null !== $origin) {
            $this->origin = (string)$origin;
        } else {
            $this->origin = null;
        }
    }

    /**
     * @return null|string
     */
    public function getOrigin()
    {
        return $this->origin;
    }

    /**
     * @param string $key
     * @return $this
     */
    public function setKey($key)
    {
        $this->key = (string)$key;
        return $this;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param string $path
     * @return $this
     */
    public function setPath($path)
    {
        $this->path = $path;
        return $this;
    }

    /**
     * @return string
     */
    public function getPath()
    {
        return $this->path;
    }

    
    /**
     * @param LoopInterface $loop
     * @return $this
     */
    public function setLoop(LoopInterface $loop)
    {
        $this->loop = $loop;
        return $this;
    }

    /**
     * @return LoopInterface
     */
    public function getLoop()
    {
        return $this->loop;
    }

    /**
     * @param $payload
     * @param string $type
     * @param bool $masked
     * @return bool|string
     */
    private function hybi10Encode($payload, $type = 'text', $masked = true)
    {
        $frameHead = array();
        $frame = '';
        $payloadLength = strlen($payload);

        switch ($type) {
            case 'text':
                // first byte indicates FIN, Text-Frame (10000001):
                $frameHead[0] = 129;
                break;

            case 'close':
                // first byte indicates FIN, Close Frame(10001000):
                $frameHead[0] = 136;
                break;

            case 'ping':
                // first byte indicates FIN, Ping frame (10001001):
                $frameHead[0] = 137;
                break;

            case 'pong':
                // first byte indicates FIN, Pong frame (10001010):
                $frameHead[0] = 138;
                break;
        }

        // set mask and payload length (using 1, 3 or 9 bytes)
        if ($payloadLength > 65535) {
            $payloadLengthBin = str_split(sprintf('%064b', $payloadLength), 8);
            $frameHead[1] = ($masked === true) ? 255 : 127;
            for ($i = 0; $i < 8; $i++) {
                $frameHead[$i + 2] = bindec($payloadLengthBin[$i]);
            }

            // most significant bit MUST be 0 (close connection if frame too big)
            if ($frameHead[2] > 127) {
                $this->close(1004);
                return false;
            }
        } elseif ($payloadLength > 125) {
            $payloadLengthBin = str_split(sprintf('%016b', $payloadLength), 8);
            $frameHead[1] = ($masked === true) ? 254 : 126;
            $frameHead[2] = bindec($payloadLengthBin[0]);
            $frameHead[3] = bindec($payloadLengthBin[1]);
        } else {
            $frameHead[1] = ($masked === true) ? $payloadLength + 128 : $payloadLength;
        }

        // convert frame-head to string:
        foreach (array_keys($frameHead) as $i) {
            $frameHead[$i] = chr($frameHead[$i]);
        }

        if ($masked === true) {
            // generate a random mask:
            $mask = array();
            for ($i = 0; $i < 4; $i++) {
                $mask[$i] = chr(rand(0, 255));
            }

            $frameHead = array_merge($frameHead, $mask);
        }
        $frame = implode('', $frameHead);
        // append payload to frame:
        for ($i = 0; $i < $payloadLength; $i++) {
            $frame .= ($masked === true) ? $payload[$i] ^ $mask[$i % 4] : $payload[$i];
        }

        return $frame;
    }

    /**
     * @param $data
     * @return null|string
     */
    private function hybi10Decode($data)
    {
        if (empty($data)) {
            return null;
        }

        $bytes = $data;
        $dataLength = '';
        $mask = '';
        $coded_data = '';
        $decodedData = '';
        $secondByte = sprintf('%08b', ord($bytes[1]));
        $masked = ($secondByte[0] == '1') ? true : false;
        $dataLength = ($masked === true) ? ord($bytes[1]) & 127 : ord($bytes[1]);

        if ($masked === true) {
            if ($dataLength === 126) {
                $mask = substr($bytes, 4, 4);
                $coded_data = substr($bytes, 8);
            } elseif ($dataLength === 127) {
                $mask = substr($bytes, 10, 4);
                $coded_data = substr($bytes, 14);
            } else {
                $mask = substr($bytes, 2, 4);
                $coded_data = substr($bytes, 6);
            }
            for ($i = 0; $i < strlen($coded_data); $i++) {
                $decodedData .= $coded_data[$i] ^ $mask[$i % 4];
            }
        } else {
            if ($dataLength === 126) {
                $decodedData = substr($bytes, 4);
            } elseif ($dataLength === 127) {
                $decodedData = substr($bytes, 10);
            } else {
                $decodedData = substr($bytes, 2);
            }
        }

        return $decodedData;
    }
}
