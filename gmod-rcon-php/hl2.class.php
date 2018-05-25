<?php
    define('PACKET_SIZE', '1400');
    define('SERVERQUERY_INFO', "\xFF\xFF\xFF\xFFTSource Engine Query");
    define ('REPLY_INFO', "\x49");
    define('SERVERQUERY_GETCHALLENGE', "\xFF\xFF\xFF\xFF\x57");
    define ('REPLY_GETCHALLENGE', "\x41");
    define('SERVERDATA_AUTH', 3) ;
    define ('SERVERDATA_EXECCOMMAND', 2) ;
	
    class srcds
    {
		function return_first_token( $arr, $num ) {
			$x=0;
			$flag=1;
			$tokens=count( $arr );
			while ($x <= $tokens)
			{
				if ($arr[$x] != null)
				{
					if ($flag == $num)
						  return $arr[$x];
					$flag++;
				}
				$x++;
			}
		}
		
		function srcds_query_hl2($ip, $port)
		{
			$time_begin=$this->microtime_float();

			$query = "\377\377\377\377TSource Engine Query\0";
			$socket = fsockopen("udp://".$ip, $port, $errno, $errstr, 1);
			socket_set_timeout($socket, 1);
			fwrite($socket, $query); $junk = fread($socket, 4);
			$status = socket_get_status($socket);

			if($status["unread_bytes"] == 0)
				return false;
			
			while($status["unread_bytes"] != 0)
			{
				$str = fread($socket, 1);
				$stats .= $str;
				$status = socket_get_status($socket);
			}
			fclose($socket);

			$x = 0;
			while ($x <= strlen($stats))
			{
				$x++;
				$result.= substr($stats, $x, 1);    
			}
			
			if (strlen(trim($result)) == 0)
				return false;
			
			$time_end=$this->microtime_float();
			$this->response = $time_end - $time_begin;
			$this->response = ($this->response * 1000);
			$this->response = (int)$this->response;
			
			return array($result, $this->response);
		}
		
		function srcds_validate()
		{
			$buffer=$this->buffer;
			$pos=strpos($buffer,"Bad rcon_password.");
			if ($pos !== false)
			{
				return 'bad-rcon-password';
			}
			$pos=strpos($buffer,"You have been banned from this server.");
			if ($pos !== false)
			{
				return 'banned-from-server';
			}
			return true;
		}

		function microtime_float()
		{
			list($usec, $sec) = explode(" ", microtime());
			return ((float)$usec + (float)$sec);
		}
		        
        function getByte(&$string)
        {
            $data = substr($string, 0, 1);
            $string = substr($string, 1);
            $data = unpack('Cvalue', $data);
            return $data['value'];
        }
    
        function getShortUnsigned(&$string)
        {
            $data = substr($string, 0, 2);
            $string = substr($string, 2);
            $data = unpack('nvalue', $data);
            return $data['value'];
        }
    
        function getShortSigned(&$string)
        {
            $data = substr($string, 0, 2);
            $string = substr($string, 2);
            $data = unpack('svalue', $data);
            return $data['value'];
        }
    
        function getLong(&$string)
        {
            $data = substr($string, 0, 4);
            $string = substr($string, 4);
            $data = unpack('Vvalue', $data);
            return $data['value'];
        }
    
        function getFloat(&$string)
        {
            $data = substr($string, 0, 4);
            $string = substr($string, 4);
            $array = unpack("fvalue", $data);
            return $array['value'];
        }
    
        function getString(&$string)
        {
            $data = "";
            $byte = substr($string, 0, 1);
            $string = substr($string, 1);
            while (ord($byte) != "0")
            {
                    $data .= $byte;
                    $byte = substr($string, 0, 1);
                    $string = substr($string, 1);
            }
            return $data;
        }

        function srcds_ping($ip, $port, $password)
        {
            $requestId = 1;
            $s2 = '';
			
			$time_begin=$this->microtime_float();
			
            $socket = @fsockopen ('tcp://'.$ip, $port, $errno, $errstr, 0.5);
            if (!$socket)
                return false;
            $data = pack("VV", $requestId, SERVERDATA_AUTH).$password.chr(0).$s2.chr(0);
            $data = pack("V",strlen($data)).$data;        
            fwrite ($socket, $data, strlen($data));
            
            $requestId++ ;
            $junk = fread ($socket, PACKET_SIZE);
            $string = fread ($socket, PACKET_SIZE);

			$time_end=$this->microtime_float();
			$this->response = $time_end - $time_begin;
			$this->response = ($this->response * 1000);
			$this->response = (int)$this->response;
			
			fclose($socket);
			return $this->response;  
        }
		
		function srcds_connect($ip, $port)
		{
            $socket = @fsockopen ('tcp://'.$ip, $port, $errno, $errstr, 0.5);
            if (!$socket)
                return false;
			else
				return true;
		}
		
        function srcds_rcmd($ip, $port, $password, $command)
        {
            $requestId = 1;
            $s2 = '';			
            $socket = @fsockopen ('tcp://'.$ip, $port, $errno, $errstr, 0.5);
            if (!$socket)
                echo $errstr;
            $data = pack("VV", $requestId, SERVERDATA_AUTH).$password.chr(0).$s2.chr(0);
            $data = pack("V",strlen($data)).$data;        
            fwrite ($socket, $data, strlen($data));
            $requestId++ ;
            $junk = fread ($socket, PACKET_SIZE);
            $string = fread ($socket, PACKET_SIZE);
            $size = $this->getLong($string);
            $id = $this->getLong($string) ;
            if ($id == -1)
				return false;
            
            $data = pack ("VV", $requestId, SERVERDATA_EXECCOMMAND).$command.chr(0).$s2.chr(0) ;
            $data = pack ("V", strlen ($data)).$data ;
            fwrite ($socket, $data, strlen($data)) ;
            $requestId++ ;
            $i = 0 ;
            $text = '' ;
            
            while ($string = fread($socket, 4))
            {				echo $string;
				$info[$i]['size'] = $this->getLong($string) ;
				$string = fread($socket, $info[$i]['size']) ;
				$info[$i]['id'] = $this->getLong ($string) ;
				$info[$i]['type'] = $this->getLong ($string) ;
				$info[$i]['s1'] = $this->getString ($string) ;
				$info[$i]['s2'] = $this->getString ($string) ;
				$text .= $info[$i]['s1'];
				$i++ ;
				$this->buffer=$text;
				if ($this->srcds_validate() !== true)
					return $this->srcds_validate();
				return $text;
            }
        }
		
		function srcds_status($type)
		{
			switch ($type)
			{
				case 'css':
					return $this->srcds_status_css();
				break;
				case 'tf2':
					return $this->srcds_status_tf2();
				break;
				default:
					return $this->srcds_status_css();
			}
			return false;
		}
		
		function srcds_status_css()
		{
			$buffer = $this->buffer;
			$lines = split("\n", $buffer);
			$players=array();
			$i=0;
			$titles = false;
			foreach ($lines as $line)
			{
				if (strpos($line, "hostname") === 0)
				{
					$this->hostname=substr($line,strpos($line, ':')+1);
				}
				if (strpos($line, "map") === 0)
				{
					$tokens=split(chr(32),substr($line,strpos($line, ':')+1));
					$this->map=$this->return_first_token( $tokens, 1 );
				}
				if (strpos($line, "players") === 0)
				{
					$tokens=split(chr(32),substr($line,strpos($line, ':')+1));
					$this->active_players=$this->return_first_token( $tokens, 1 );
					$this->max_players=str_replace("(","",$this->return_first_token( $tokens, 2 ));
				}
				if ($titles == true && strlen(trim($line)) > 0)
				{
					$pos=strrpos($line,'"')+1;
					$temp=substr($line,$pos,strlen($line));
					$tokens=split(chr(32),$temp);
					$temp=split('"',$line);
					$name=$temp[1];
					$players[] = array(
						"userid" => $this->return_first_token( split(chr(32),$line), 2 ),
						"name" => $name,
						"uniqueid" => $this->return_first_token( $tokens, 1 ),
						"time" => $this->return_first_token( $tokens, 2 ),
						"ping" => $this->return_first_token( $tokens, 3 )." ms",
						"loss" => $this->return_first_token( $tokens, 4 ),
						"state" => $this->return_first_token( $tokens, 5 ),
						"ip" => $this->return_first_token( $tokens, 6 ),
					);
					$this->players=$players;
				}
				if (strpos($line, "#") === 0)
				{
					$titles = true;
				}
				$i++;
			}
			return array($this->hostname, $this->map, $this->active_players, $this->max_players, $this->players);
		}

		function srcds_status_tf2()
		{
			$buffer = $this->buffer;
			$lines = split("\n", $buffer);
			$players=array();
			$i=0;
			$titles = false;
			foreach ($lines as $line)
			{
				if (strpos($line, "hostname") === 0)
				{
					$this->hostname=substr($line,strpos($line, ':')+1);
				}
				if (strpos($line, "map") === 0)
				{
					$tokens=split(chr(32),substr($line,strpos($line, ':')+1));
					$this->map=$this->return_first_token( $tokens, 1 );
				}
				if (strpos($line, "players") === 0)
				{
					$tokens=split(chr(32),substr($line,strpos($line, ':')+1));
					$this->active_players=$this->return_first_token( $tokens, 1 );
					$this->max_players=str_replace("(","",$this->return_first_token( $tokens, 2 ));
				}
				if ($titles == true && strlen(trim($line)) > 0)
				{
					$pos=strrpos($line,'"')+1;
					$temp=substr($line,$pos,strlen($line));
					$tokens=split(chr(32),$temp);
					$temp=split('"',$line);
					$name=$temp[1];
					$players[] = array(
						"userid" => $this->return_first_token( split(chr(32),$line), 2 ),
						"name" => $name,
						"uniqueid" => $this->return_first_token( $tokens, 1 ),
						"time" => $this->return_first_token( $tokens, 2 ),
						"ping" => $this->return_first_token( $tokens, 3 )." ms",
						"loss" => $this->return_first_token( $tokens, 4 ),
						"state" => $this->return_first_token( $tokens, 5 ),
						"ip" => $this->return_first_token( $tokens, 6 ),
					);
					$this->players=$players;
				}
				if (strpos($line, "#") === 0)
				{
					$titles = true;
				}
				$i++;
			}
			return array($this->hostname, $this->map, $this->active_players, $this->max_players, $this->players);
		}
		
		function srcds_cvar_value()
		{
			$cvar=$this->rcmd;
			$cvar_value=$this->buffer;
			$temp=split(' ', $cvar_value);
			$this->cvar=str_replace('"','',$temp[2]);
			return trim($this->cvar);
		}

		function srcds_stats()
		{
			$buffer = $this->buffer;
			$lines = split("\n", $buffer);
			$stats=array();
			$i=0;
			foreach ($lines as $line)
			{
				if ($i == 1)
				{
					$tokens=split(chr(32),$line);
					$stats = array(
						"cpu" => $this->return_first_token( $tokens, 1 )."%",
						"in" => $this->return_first_token( $tokens, 2 )." kb/s",
						"out" => $this->return_first_token( $tokens, 3 )." kb/s",
						"uptime" => $this->return_first_token( $tokens, 4 ),
						"users" => $this->return_first_token( $tokens, 5 ),
						"fps" => $this->return_first_token( $tokens, 6 ) ." fps",
						"players" => $this->return_first_token( $tokens, 7 ),
					);
					$this->stats=$stats;
				}
				$i++;
			}
			return $stats;
		}
		
		function srcds_version()
		{
			$buffer=$this->buffer;
			$lines = split("\n", $buffer);
			$version=array();
			$i=0;
			foreach ($lines as $line)
			{
				if ($i == 0)
				{
					$tokens=split(chr(32),$line);
					$protocol=$tokens[2];
				}
				if ($i == 1)
				{
					$tokens=split(chr(32),substr($line, 12));
					$version=$tokens[0];
					$gamedir=str_replace(")","",str_replace("(","",$tokens[1]));
				}
				if ($i == 2)
				{
					$tokens=substr($line, 11);
					$pos=strpos($tokens,"(")-1;
					$time=substr($tokens,0,$pos);
					$build=str_replace(")","",str_replace("(","",substr($tokens,$pos+1)));
				}
				$i++;
			}
			$version = array(
				"protocol" => $protocol,
				"version" => $version,
				"gamedir" => $gamedir,
				"build" => $build,
				"time" => $time,
			);
			$this->version=$version;
			return $version;
		}
    }
?>