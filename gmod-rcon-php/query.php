<?php
	$server = "80.149.2.5:27015";
	$rcon = "changeme";
	$cmd = "status";
	include_once('hl2.class.php');
	$srcds = new srcds();
	$ip  = strtok($server, ':');
	$port  = strtok(':');
	$buff = $srcds->srcds_rcmd ( $ip, $port, $rcon, $cmd );
	return $buff;
?>