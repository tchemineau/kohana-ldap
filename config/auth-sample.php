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
				'ssl'     => false,

				// Here, define mapping between internal variables and
				// LDAP attributes.
				// Add your own internal variables which will be stored
				// in session and could be retrieve by $auth->get_user()
				'mapping' => array(
					'user' => array (
						'username'  => 'uid',
						'firstname' => 'sn',
						'lastname'  => 'cn',
						'email'     => 'mail'
					),
				),
			),

		),

		'order' => 'default',

	),

);

