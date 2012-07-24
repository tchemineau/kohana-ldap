<?php defined('SYSPATH') or die('No direct access allowed.');

return array(

	'ldap1' => array (

		'type'    => 'ldap',

		// Connection parameters
		'connection' => array (

			'uri'     => 'ldap://localhost/',
			'binddn'  => '',
			'bindpw'  => '',
			'version' => 3,
			'ssl'     => false,

		),

		// Here, define default searches.
		'search' => array (

			// Default values for user search
			'user' => array (

				'basedn'  => 'ou=people,dc=example,dc=org',
				'filter'  => '(&(objectClass=person)(uid=%u))',
				'scope'   => 'one'

			),

		),

		// Here, define mapping between internal variables and
		// LDAP attributes.
		// Add your own internal variables which will be stored
		// in session and could be retrieve by $auth->get_user()
		'mapping' => array (

			// Default values for user mapping
			'user' => array (

				'username'  => 'uid',
				'firstname' => 'sn',
				'lastname'  => 'cn',
				'email'     => 'mail'

			),

		),

	),

);

