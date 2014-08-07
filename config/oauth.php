<?php defined('SYSPATH') or die('No direct access allowed.');

return array(
	'authentification_url' => 'oauth/authorize',
	'type' => array(
		1 => 'request',
		2 => 'access',
	),
	'token' => array(
		'expir' => 60,
	),
);
