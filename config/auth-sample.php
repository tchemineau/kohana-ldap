<?php defined('SYSPATH') or die('No direct access allowed.');

return array(

	'driver' => 'ldap',

	'ldap' => array (

		'server' => array (

			'default' => array (
				'uri'     => 'ldap://localhost/',
				'basedn'  => 'ou=people,dc=example,dc=org',
				'binddn'  => '',
				'bindpw'  => '',
				'filter'  => '(&(objectClass=person)(uid=%u))',
				'version' => 3,
				'ssl'     => false
			),

		),

		'order' => 'default',

	),

);

