<?php defined('SYSPATH') or die('No direct access allowed.');

return array(

	'driver' => 'ldap',

	'ldap' => array (

		// Verify or not the password of the user
		'force' => false,

		// Order of LDAP databases
		'order' => array( 'ldap1' ),

	),

);

