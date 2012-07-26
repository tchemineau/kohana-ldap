<?php defined('SYSPATH') or die('No direct access allowed.');

/**
 * LDAP database class.
 *
 * @package    Kohana/LDAP
 * @author     Thomas Chemineau - thomas.chemineau@gmail.com
 * @copyright (c) 2007-2012 Thomas Chemineau
 * @license    http://kohanaframework.org/license
 */
class Kohana_Database_Ldap extends Database
{

	/**
	 * Initialize default parameters and call Database constructor.
	 *
	 * @return  void
	 */
	protected function __construct ( $name, array $config )
	{
		// Search parameters
		if (!isset($config['search']))
		{
			$config['search'] = array ();
		}
		if (!isset($config['search']['user']))
		{
			$config['search']['user'] = array ();
		}
		if (!isset($config['search']['user']['filter']))
		{
			$config['search']['user']['filter'] = '(&(objectClass=person)(uid=%u))';
		}
		if (!isset($config['search']['user']['basedn']))
		{
			$config['search']['user']['basedn'] = 'ou=people,dc=example,dc=org';
		}
		if (!isset($config['search']['user']['scope']))
		{
			$config['search']['user']['scope'] = 'one';
		}

		// Mapping parameters
		if (!isset($config['mapping']))
		{
			$config['mapping'] = array();
		}
		if (!isset($config['mapping']['user']))
		{
			$config['mapping']['user'] = array();
		}

		// Call parent contructor
		parent::__construct($name, $config);
	}

	/**
	 * Bind to a given user.
	 *
	 * @param   string  User DN
	 * @param   string  User password
	 * @return  boolean
	 */
	public function bind ( $dn, $password )
	{
		if (!$this->connect())
		{
			return FALSE;
		}
		return @ldap_bind($this->_connection, $dn, $password);
	}

	/**
	 * Connect to the LDAP directory.
	 *
	 * @param   array   $this->_config   Parameters to connect to a LDAP server
	 * @return  boolean
	 */
	public function connect ()
	{
		if ($this->_connection)
		{
			return TRUE;
		}
		if (!isset($this->_config['connection']) || !isset($this->_config['connection']['uri']))
		{
			return FALSE;
		}
		if (isset($this->_config['connection']['ssl']) && $this->_config['connection']['ssl'])
		{
			$this->_connection = @ldap_connect($this->_config['connection']['uri']);
			if ($this->_connection && !@ldap_start_tls($this->_connection))
			{
				$this->disconnect();
				$uri = 'ldaps://' . preg_replace('#ldaps?://#', '', $this->_config['connection']['uri']);
				if (preg_match('/:[0-9]+/', $uri) == 0)
				{
					$this->_config['connection']['uri'] = ':636';
				}
			}
		}
		if (!$this->_connection)
		{
			$this->_connection = @ldap_connect($this->_config['connection']['uri']);
		}
		if ($this->_connection === false)
		{
			return FALSE;
		}
		if (!isset($this->_config['connection']['version']))
		{
			$this->_config['connection']['version'] = 3;
		}
		if ($this->_config['connection']['version'] == 3)
		{
			ldap_set_option($this->_connection, LDAP_OPT_PROTOCOL_VERSION, 3) ;
		}
		if (isset($this->_config['connection']['binddn']) && isset($this->_config['connection']['bindpw']))
		{
			$binddn = is_null($this->_config['connection']['binddn']) ? '' : $this->_config['connection']['binddn'];
			$bindpw = is_null($this->_config['connection']['bindpw']) ? '' : $this->_config['connection']['bindpw'];
			if (strlen($binddn) > 0 && strlen($bindpw) > 0 && !@ldap_bind($this->_connection, $binddn, $bindpw))
			{
				return FALSE;
			}
		}
		else if (!@ldap_bind($this->_connection))
		{
			return FALSE;
		}
		return TRUE;
	}

	/**
	 * Close this LDAP connection.
	 *
	 * @return boolean
	 */
	public function disconnect()
	{
		if ($this->_connection)
		{
			ldap_close($this->_connection);
		}
		return parent::disconnect();
	}

	/**
	 * Format a filter.
	 *
	 * @param   string   $filter   A LDAP filter
	 * @param   array    $vars     Variables to replace
	 * @return  string
	 */
	public static function format_filter ( $filter, $vars )
	{
		foreach ($vars as $var => $val)
		{
			$filter = preg_replace('/\%'.$var.'/', $val, $filter);
		}
		return $filter;
	}

	/**
	 * Get configuration.
	 *
	 * @return array
	 */
	public function get_config ()
	{
		return $this->_config;
	}

        /**
         * Get instance name.
         *
         * @return string
         */
        public function get_name ()
        {
                return $this->_instance;
        }

	/**
	 * Perform a LDAP query of the given type.
	 *
	 *     // Make a SEARCH query and use objects for results
	 *     $db->query(Database::SELECT, array('filter' => '(objectClass=person)', 'basedn' => 'ou=people,dc=example,dc=com'), TRUE);
	 *
	 *     // Make a SELECT query and use "Model_User" for the results
	 *     $db->query(Database::SELECT, array('filter' => '(&(objectClass=person)(uid=test))', 'basedn' => 'ou=people,dc=example,dc=com'), 'Model_User');
	 *
	 *     // Specify the search scope
	 *     $db->query(Database::SELECT, array('filter' => '(objectClass=person)', 'basedn' => 'ou=people,dc=example,dc=com', 'scope' => 'one'));
	 *
	 * @param   integer  Database::SELECT, Database::INSERT, etc
	 * @param   string   LDAP query
	 * @param   mixed    result object class string, TRUE for stdClass, FALSE for assoc array
	 * @param   array    object construct parameters for result class
	 * @return  object   Database_Result for SELECT queries
	 * @return  array    list (insert id, row count) for INSERT queries
	 * @return  integer  number of affected rows for all other queries
	 */
	public function query ( $type, $query, $as_object = FALSE, array $params = NULL )
	{
		if (!$this->connect())
		{
			return -1;
		}
		if (!is_array($query))
		{
			return -1;
		}
		switch($type)
		{
			case Database::SELECT:
				if (!isset($query['filter']) || !isset($query['basedn']))
				{
					return -1;
				}
				if (!isset($query['scope']))
				{
					$query['scope'] = 'one';
				}
				if (!isset($query['attributes']))
				{
					$query['attributes'] = array();
				}
				$entries = $this->_search(
					$query['filter'],
					$query['basedn'],
					$query['scope'],
					$query['attributes']
				);
				if (is_array($entries))
				{
					return $entries;
				}
		}
		return -1;
	}

	/**
	 * Set the connection character set. This is called automatically by [Database::connect].
	 * Not needed by LDAP: it's UTF8.
	 *
	 * @throws  Database_Exception
	 * @param   string   character set name
	 * @return  void
	 */
	public function set_charset ( $charset ) { }

	/**
	 * LDAP does not support transaction
	 *
	 * @param string transaction mode
	 * @return  boolean
	 */
	public function begin ( $mode = NULL )
	{
		return FALSE;
	}

	/**
	 * LDAP does not support transaction
	 *
	 * @return  boolean
	 */
	public function commit ()
	{
		return FALSE;
	}

	/**
	 * LDAP does not support transaction
	 *
	 * @return  boolean
	 */
	public function rollback ()
	{
		return FALSE;
	}

	/**
	 * No tables into LDAP server
	 *
	 * @param   string   table to search for
	 * @return  array
	 */
	public function list_tables ( $like = NULL )
	{
		return array();
	}

	/**
	 * No columns into LDAP server
	 *
	 * @param   string  table to get columns from
	 * @param   string  column to search for
	 * @param   boolean whether to add the table prefix automatically or not
	 * @return  array
	 */
	public function list_columns ( $table, $like = NULL, $add_prefix = TRUE )
	{
		return array();
	}

	/**
	 * Sanitize a string by escaping characters that could cause an SQL
	 * injection attack.
	 *
	 *     $value = $db->escape('any string');
	 *
	 * @param   string   value to quote
	 * @return  string
	 */
	public function escape ( $value )
	{
		return $value;
	}

	/**
	 * Search for LDAP entries.
	 *
	 * @param   string   $filter    LDAP filter
	 * @param   string   $basedn    LDAP base dn
	 * @param   string   $scope     Search scope (base, one or sub)
	 * @param   array    $attrs     Attributes to return
	 * @return  array|false
	 */
	protected function _search ( $filter, $basedn, $scope = 'one', $attrs = array() )
	{
		if (!$this->_connection)
		{
			return FALSE;
		}

		if (sizeof($attrs) == 0)
		{
			$attrs = array( 'dn' );
		}
		else
		{
			$attrs = array_values($attrs);
		}

		switch ($scope)
		{
			case 'base':
				$search_result = @ldap_read($this->_connection, $basedn, $filter, $attrs);
				break;
			case 'one':
				$search_result = @ldap_list($this->_connection, $basedn, $filter, $attrs);
				break;
			case 'sub':
				$search_result = @ldap_search($this->_connection, $basedn, $filter, $attrs);
			default:
				return false;
		}

		if (!$search_result)
		{
			return FALSE;
		}

		$entries = @ldap_get_entries($this->_connection, $search_result);
		if (is_array($entries) && sizeof($entries) > 0)
		{
			$entriesb = array();
			foreach ($entries as $index => $values)
			{
				if (is_array($values) && !is_null($values['dn']))
				{
					foreach ($values as $k => $v)
					{
						if (is_numeric($k))
						{
							unset($values[$k]);
						}
						else if (is_array($v) && isset($v['count']))
						{
							unset($values[$k]['count']);
						}
					}
					$entriesb[$values['dn']] = $values;
					unset($entriesb[$values['dn']]['count']);
				}
			}
			return $entriesb;
		}

		return FALSE;
	}

} // End Auth LDAP

