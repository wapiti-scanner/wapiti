<?php
/**
 * Runtime for Jetpack Waf
 *
 * @package automattic/jetpack-waf
 */

namespace Automattic\Jetpack\Waf;

use Automattic\Jetpack\IP\Utils as IP_Utils;

require_once __DIR__ . '/functions.php';

// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- This class is all about sanitizing input.

/**
 * The environment variable that defined the WAF running mode.
 *
 * @var string JETPACK_WAF_MODE
 */

/**
 * Waf_Runtime class
 *
 * @template Target as array{ only?: string[], except?: string[], count?: boolean }
 * @template TargetBag as array<string, Target>
 */
class Waf_Runtime {
	/**
	 * If used, normalize_array_targets() will just return the number of matching values, instead of the values themselves.
	 */
	const NORMALIZE_ARRAY_COUNT = 1;
	/**
	 * If used, normalize_array_targets() will apply "only" and "except" filters to the values of the source array, instead of the keys.
	 */
	const NORMALIZE_ARRAY_MATCH_VALUES = 2;

	/**
	 * Last rule.
	 *
	 * @var string
	 */
	public $last_rule = '';
	/**
	 * Matched vars.
	 *
	 * @var array
	 */
	public $matched_vars = array();
	/**
	 * Matched var.
	 *
	 * @var string
	 */
	public $matched_var = '';
	/**
	 * Matched var names.
	 *
	 * @var array
	 */
	public $matched_var_names = array();
	/**
	 * Matched var name.
	 *
	 * @var string
	 */
	public $matched_var_name = '';

	/**
	 * State.
	 *
	 * @var array
	 */
	private $state = array();
	/**
	 * Metadata.
	 *
	 * @var array
	 */
	private $metadata = array();

	/**
	 * Transforms.
	 *
	 * @var Waf_Transforms
	 */
	private $transforms;
	/**
	 * Operators.
	 *
	 * @var Waf_Operators
	 */
	private $operators;

	/**
	 * The request
	 *
	 * @var Waf_Request
	 */
	private $request;

	/**
	 * Rules to remove.
	 *
	 * @var array[]
	 */
	private $rules_to_remove = array(
		'id'  => array(),
		'tag' => array(),
	);

	/**
	 * Targets to remove.
	 *
	 * @var array[]
	 */
	private $targets_to_remove = array(
		'id'  => array(),
		'tag' => array(),
	);

	/**
	 * Constructor method.
	 *
	 * @param Waf_Transforms $transforms Transforms.
	 * @param Waf_Operators  $operators  Operators.
	 * @param Waf_Request?   $request    Information about the request.
	 */
	public function __construct( $transforms, $operators, $request = null ) {
		$this->transforms = $transforms;
		$this->operators  = $operators;
		$this->request    = null === $request
			? new Waf_Request()
			: $request;
	}

	/**
	 * Rule removed method.
	 *
	 * @param string   $id Ids.
	 * @param string[] $tags Tags.
	 */
	public function rule_removed( $id, $tags ) {
		if ( isset( $this->rules_to_remove['id'][ $id ] ) ) {
			return true;
		}
		foreach ( $tags as $tag ) {
			if ( isset( $this->rules_to_remove['tag'][ $tag ] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Update Targets.
	 *
	 * @param array    $targets Targets.
	 * @param string   $rule_id Rule id.
	 * @param string[] $rule_tags Rule tags.
	 */
	public function update_targets( $targets, $rule_id, $rule_tags ) {
		$updates = array();
		// look for target updates based on the rule's ID.
		if ( isset( $this->targets_to_remove['id'][ $rule_id ] ) ) {
			foreach ( $this->targets_to_remove['id'][ $rule_id ] as $name => $props ) {
				$updates[] = array( $name, $props );
			}
		}
		// look for target updates based on the rule's tags.
		foreach ( $rule_tags as $tag ) {
			if ( isset( $this->targets_to_remove['tag'][ $tag ] ) ) {
				foreach ( $this->targets_to_remove['tag'][ $tag ] as $name => $props ) {
					$updates[] = array( $name, $props );
				}
			}
		}
		// apply any found target updates.

		foreach ( $updates as list( $name, $props ) ) {
			if ( isset( $targets[ $name ] ) ) {
				// we only need to remove targets that exist.
				if ( true === $props ) {
					// if the entire target is being removed, remove it.
					unset( $targets[ $name ] );
				} else {
					// otherwise just mark single props to ignore.
					$targets[ $name ]['except'] = array_merge(
						isset( $targets[ $name ]['except'] ) ? $targets[ $name ]['except'] : array(),
						$props
					);
				}
			}
		}
		return $targets;
	}

	/**
	 * Return TRUE if at least one of the targets matches the rule.
	 *
	 * @param string[]  $transforms One of the transform methods defined in the Jetpack Waf_Transforms class.
	 * @param TargetBag $targets Targets.
	 * @param string    $match_operator Match operator.
	 * @param mixed     $match_value Match value.
	 * @param bool      $match_not Match not.
	 * @param bool      $capture Capture.
	 * @return bool
	 */
	public function match_targets( $transforms, $targets, $match_operator, $match_value, $match_not, $capture = false ) {
		$this->matched_vars      = array();
		$this->matched_var_names = array();
		$this->matched_var       = '';
		$this->matched_var_name  = '';
		$match_found             = false;

		// get values.
		$values = $this->normalize_targets( $targets );

		// apply transforms.
		foreach ( $transforms as $t ) {
			foreach ( $values as &$v ) {
				$v['value'] = $this->transforms->$t( $v['value'] );
			}
		}

		// pass each target value to the operator to find any that match.
		$matched  = array();
		$captures = array();
		foreach ( $values as $v ) {
			$match     = $this->operators->{$match_operator}( $v['value'], $match_value );
			$did_match = false !== $match;
			if ( $match_not !== $did_match ) {
				// If either:
				// - rule is negated ("not" flag set) and the target was not matched
				// - rule not negated and the target was matched
				// then this is considered a match.
				$match_found               = true;
				$this->matched_var_names[] = $v['source'];
				$this->matched_vars[]      = $v['value'];
				$this->matched_var_name    = end( $this->matched_var_names );
				$this->matched_var         = end( $this->matched_vars );
				$matched[]                 = array( $v, $match );
				// Set any captured matches into state if the rule has the "capture" flag.
				if ( $capture ) {
					$captures = is_array( $match ) ? $match : array( $match );
					foreach ( array_slice( $captures, 0, 10 )  as $i => $c ) {
						$this->set_var( "tx.$i", $c );
					}
				}
			}
		}

		return $match_found;
	}

	/**
	 * Block.
	 *
	 * @param string $action Action.
	 * @param string $rule_id Rule id.
	 * @param string $reason Block reason.
	 * @param int    $status_code Http status code.
	 */
	public function block( $action, $rule_id, $reason, $status_code = 403 ) {
		if ( ! $reason ) {
			$reason = "rule $rule_id";
		} else {
			$reason = $this->sanitize_output( $reason );
		}

		$this->write_blocklog( $rule_id, $reason );
		error_log( "Jetpack WAF Blocked Request\t$action\t$rule_id\t$status_code\t$reason" );
		header( "X-JetpackWAF-Blocked: $status_code - rule $rule_id" );
		if ( defined( 'JETPACK_WAF_MODE' ) && 'normal' === JETPACK_WAF_MODE ) {
			$protocol = isset( $_SERVER['SERVER_PROTOCOL'] ) ? wp_unslash( $_SERVER['SERVER_PROTOCOL'] ) : 'HTTP';
			header( $protocol . ' 403 Forbidden', true, $status_code );
			die( "rule $rule_id - reason $reason" );
		}
	}

	/**
	 * Write block logs. We won't write to the file if it exceeds 100 mb.
	 *
	 * @param string $rule_id Rule id.
	 * @param string $reason Block reason.
	 */
	public function write_blocklog( $rule_id, $reason ) {
		$log_data              = array();
		$log_data['rule_id']   = $rule_id;
		$log_data['reason']    = $reason;
		$log_data['timestamp'] = gmdate( 'Y-m-d H:i:s' );

		if ( defined( 'JETPACK_WAF_SHARE_DATA' ) && JETPACK_WAF_SHARE_DATA ) {
			$file_path   = JETPACK_WAF_DIR . '/waf-blocklog';
			$file_exists = file_exists( $file_path );

			if ( ! $file_exists || filesize( $file_path ) < ( 100 * 1024 * 1024 ) ) {
				$fp = fopen( $file_path, 'a+' );

				if ( $fp ) {
					try {
						fwrite( $fp, json_encode( $log_data ) . "\n" );
					} finally {
						fclose( $fp );
					}
				}
			}
		}

		$this->write_blocklog_row( $log_data );
	}

	/**
	 * Write block logs to database.
	 *
	 * @param array $log_data Log data.
	 */
	private function write_blocklog_row( $log_data ) {
		$conn = $this->connect_to_wordpress_db();

		if ( ! $conn ) {
			return;
		}

		global $table_prefix;

		$statement = $conn->prepare( "INSERT INTO {$table_prefix}jetpack_waf_blocklog(reason,rule_id, timestamp) VALUES (?, ?, ?)" );
		if ( false !== $statement ) {
			$statement->bind_param( 'sis', $log_data['reason'], $log_data['rule_id'], $log_data['timestamp'] );
			$statement->execute();

			if ( $conn->insert_id > 100 ) {
				$conn->query( "DELETE FROM {$table_prefix}jetpack_waf_blocklog ORDER BY log_id LIMIT 1" );
			}
		}
	}

	/**
	 * Connect to WordPress database.
	 */
	private function connect_to_wordpress_db() {
		if ( ! file_exists( JETPACK_WAF_WPCONFIG ) ) {
			return;
		}

		require_once JETPACK_WAF_WPCONFIG;
		$conn = new \mysqli( DB_HOST, DB_USER, DB_PASSWORD, DB_NAME ); // phpcs:ignore WordPress.DB.RestrictedClasses.mysql__mysqli

		if ( $conn->connect_error ) {
			error_log( 'Could not connect to the database:' . $conn->connect_error );
			return null;
		}

		return $conn;
	}

	/**
	 * Redirect.
	 *
	 * @param string $rule_id Rule id.
	 * @param string $url Url.
	 */
	public function redirect( $rule_id, $url ) {
		error_log( "Jetpack WAF Redirected Request.\tRule:$rule_id\t$url" );
		header( "Location: $url" );
		exit;
	}

	/**
	 * Flag rule for removal.
	 *
	 * @param string $prop Prop.
	 * @param string $value Value.
	 */
	public function flag_rule_for_removal( $prop, $value ) {
		if ( 'id' === $prop ) {
			$this->rules_to_remove['id'][ $value ] = true;
		} else {
			$this->rules_to_remove['tag'][ $value ] = true;
		}
	}

	/**
	 * Flag target for removal.
	 *
	 * @param string $id_or_tag Id or tag.
	 * @param string $id_or_tag_value Id or tag value.
	 * @param string $name Name.
	 * @param string $prop Prop.
	 */
	public function flag_target_for_removal( $id_or_tag, $id_or_tag_value, $name, $prop = null ) {
		if ( null === $prop ) {
			$this->targets_to_remove[ $id_or_tag ][ $id_or_tag_value ][ $name ] = true;
		} elseif (
			! isset( $this->targets_to_remove[ $id_or_tag ][ $id_or_tag_value ][ $name ] )
			// if the entire target is already being removed then it would be redundant to remove a single property.
			|| true !== $this->targets_to_remove[ $id_or_tag ][ $id_or_tag_value ][ $name ]
		) {
			$this->targets_to_remove[ $id_or_tag ][ $id_or_tag_value ][ $name ][] = $prop;
		}
	}

	/**
	 * Get variable value.
	 *
	 * @param string $key Key.
	 */
	public function get_var( $key ) {
		return isset( $this->state[ $key ] )
			? $this->state[ $key ]
			: '';
	}

	/**
	 * Set variable value.
	 *
	 * @param string $key Key.
	 * @param string $value Value.
	 */
	public function set_var( $key, $value ) {
		$this->state[ $key ] = $value;
	}

	/**
	 * Increment variable.
	 *
	 * @param string $key Key.
	 * @param mixed  $value Value.
	 */
	public function inc_var( $key, $value ) {
		if ( ! isset( $this->state[ $key ] ) ) {
			$this->state[ $key ] = 0;
		}
		$this->state[ $key ] += floatval( $value );
	}

	/**
	 * Decrement variable.
	 *
	 * @param string $key Key.
	 * @param mixed  $value Value.
	 */
	public function dec_var( $key, $value ) {
		if ( ! isset( $this->state[ $key ] ) ) {
			$this->state[ $key ] = 0;
		}
		$this->state[ $key ] -= floatval( $value );
	}

	/**
	 * Unset variable.
	 *
	 * @param string $key Key.
	 */
	public function unset_var( $key ) {
		unset( $this->state[ $key ] );
	}

	/**
	 * A cache of metadata about the incoming request.
	 *
	 * @param string $key The type of metadata to request ('headers', 'request_method', etc.).
	 */
	public function meta( $key ) {
		if ( ! isset( $this->metadata[ $key ] ) ) {
			$value = null;
			switch ( $key ) {
				case 'headers':
					$value = $this->request->get_headers();
					break;
				case 'headers_names':
					$value = $this->args_names( $this->meta( 'headers' ) );
					break;
				case 'request_method':
					$value = $this->request->get_method();
					break;
				case 'request_protocol':
					$value = $this->request->get_protocol();
					break;
				case 'request_uri':
					$value = $this->request->get_uri( false );
					break;
				case 'request_uri_raw':
					$value = $this->request->get_uri( true );
					break;
				case 'request_filename':
					$value = $this->request->get_filename();
					break;
				case 'request_line':
					$value = sprintf(
						'%s %s %s',
						$this->request->get_method(),
						$this->request->get_uri( false ),
						$this->request->get_protocol()
					);
					break;
				case 'request_basename':
					$value = basename( $this->request->get_filename() );
					break;
				case 'request_body':
					$value = $this->request->get_body();
					break;
				case 'query_string':
					$value = $this->request->get_query_string();
					break;
				case 'args_get':
					$value = $this->request->get_get_vars();
					break;
				case 'args_get_names':
					$value = $this->args_names( $this->meta( 'args_get' ) );
					break;
				case 'args_post':
					$value = $this->request->get_post_vars();
					break;
				case 'args_post_names':
					$value = $this->args_names( $this->meta( 'args_post' ) );
					break;
				case 'args':
					$value = array_merge( $this->meta( 'args_get' ), $this->meta( 'args_post' ) );
					break;
				case 'args_names':
					$value = $this->args_names( $this->meta( 'args' ) );
					break;
				case 'request_cookies':
					$value = $this->request->get_cookies();
					break;
				case 'request_cookies_names':
					$value = $this->args_names( $this->meta( 'request_cookies' ) );
					break;
				case 'files':
					$value = array();
					foreach ( $this->request->get_files() as $f ) {
						$value[] = array( $f['name'], $f['filename'] );
					}
					break;
				case 'files_names':
					$value = $this->args_names( $this->meta( 'files' ) );
					break;
			}
			$this->metadata[ $key ] = $value;
		}

		return $this->metadata[ $key ];
	}

	/**
	 * State values.
	 *
	 * @param string $prefix Prefix.
	 */
	private function state_values( $prefix ) {
		$output = array();
		$len    = strlen( $prefix );
		foreach ( $this->state as $k => $v ) {
			if ( 0 === stripos( $k, $prefix ) ) {
				$output[ substr( $k, $len ) ] = $v;
			}
		}

		return $output;
	}

	/**
	 * Change a string to all lowercase and replace spaces and underscores with dashes.
	 *
	 * @param string $name Name.
	 * @return string
	 */
	public function normalize_header_name( $name ) {
		return str_replace( array( ' ', '_' ), '-', strtolower( $name ) );
	}

	/**
	 * Get match-able values from a collection of targets.
	 *
	 * This function expects an associative array of target items, and returns an array of possible values from those targets that can be used to match against.
	 * The key is the lowercase target name (i.e. `args`, `request_headers`, etc) - see https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v3.x)#Variables
	 * The value is an associative array of options that define how to narrow down the returned values for that target if it's an array (ARGS, for example). The possible options are:
	 *   count:  If `true`, then the returned value will a count of how many matched targets were found, rather then the actual values of those targets.
	 *           For example, &ARGS_GET will return the number of keys the query string.
	 *   only:   If specified, then only values in that target that match the given key will be returned.
	 *           For example, ARGS_GET:id|ARGS_GET:/^name/ will only return the values for `$_GET['id']` and any key in `$_GET` that starts with `name`
	 *   except: If specified, then values in that target will be left out from the returned values (even if they were included in an `only` option)
	 *           For example, ARGS_GET|!ARGS_GET:z will return every value from `$_GET` except for `$_GET['z']`.
	 *
	 * This function will return an array of associative arrays. Each with:
	 *   name:   The target name that this value came from (i.e. the key in the input `$targets` argument )
	 *   source: For targets that are associative arrays (like ARGS), this will be the target name AND the key in that target (i.e. "args:z" for ARGS:z)
	 *   value:  The value that was found in the associated target.
	 *
	 * @param TargetBag $targets An assoc. array with keys that are target name(s) and values are options for how to process that target (include/exclude rules, whether to return values or counts).
	 * @return array{ name: string, source: string, value: mixed }
	 */
	public function normalize_targets( $targets ) {
		$return = array();
		foreach ( $targets as $k => $v ) {
			$count_only = isset( $v['count'] ) ? self::NORMALIZE_ARRAY_COUNT : 0;
			$only       = isset( $v['only'] ) ? $v['only'] : array();
			$except     = isset( $v['except'] ) ? $v['except'] : array();
			$_k         = strtolower( $k );
			switch ( $_k ) {
				case 'request_headers':
					$this->normalize_array_target(
						// get the headers that came in with this request
						$this->meta( 'headers' ),
						// ensure only and exclude filters are normalized
						array_map( array( $this->request, 'normalize_header_name' ), $only ),
						array_map( array( $this->request, 'normalize_header_name' ), $except ),
						$k,
						$return,
						// flags
						$count_only
					);
					continue 2;
				case 'request_headers_names':
					$this->normalize_array_target( $this->meta( 'headers_names' ), $only, $except, $k, $return, $count_only | self::NORMALIZE_ARRAY_MATCH_VALUES );
					continue 2;
				case 'request_method':
				case 'request_protocol':
				case 'request_uri':
				case 'request_uri_raw':
				case 'request_filename':
				case 'request_basename':
				case 'request_body':
				case 'query_string':
				case 'request_line':
					$v = $this->meta( $_k );
					break;
				case 'tx':
				case 'ip':
					$this->normalize_array_target( $this->state_values( "$k." ), $only, $except, $k, $return, $count_only );
					continue 2;
				case 'request_cookies':
				case 'args':
				case 'args_get':
				case 'args_post':
				case 'files':
					$this->normalize_array_target( $this->meta( $_k ), $only, $except, $k, $return, $count_only );
					continue 2;
				case 'request_cookies_names':
				case 'args_names':
				case 'args_get_names':
				case 'args_post_names':
				case 'files_names':
					// get the "full" data (for 'args_names' get data for 'args') and stripe it down to just the key names
					$data = array_map(
						function ( $item ) {
							return $item[0]; },
						$this->meta( substr( $_k, 0, -6 ) )
					);
					$this->normalize_array_target( $data, $only, $except, $k, $return, $count_only | self::NORMALIZE_ARRAY_MATCH_VALUES );
					continue 2;
				default:
					var_dump( 'Unknown target', $k, $v );
					exit;
			}
			$return[] = array(
				'name'   => $k,
				'value'  => $v,
				'source' => $k,
			);
		}

		return $return;
	}

	/**
	 * Verifies if the IP from the current request is in an array.
	 *
	 * @param array $array Array of IP addresses to verify the request IP against.
	 * @return bool
	 */
	public function is_ip_in_array( $array ) {
		$real_ip      = $this->request->get_real_user_ip_address();
		$array_length = count( $array );

		for ( $i = 0; $i < $array_length; $i++ ) {
			// Check if the IP matches a provided range.
			$range = explode( '-', $array[ $i ] );
			if ( count( $range ) === 2 ) {
				if ( IP_Utils::ip_address_is_in_range( $real_ip, $range[0], $range[1] ) ) {
					return true;
				}
				continue;
			}

			// Check if the IP is an exact match.
			if ( $real_ip === $array[ $i ] ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Extract values from an associative array, potentially applying filters and/or counting results.
	 *
	 * @param array{ 0: string, 1: scalar }|scalar[] $source      The source assoc. array of values (i.e. $_GET, $_SERVER, etc.).
	 * @param string[]                               $only        Only include the values for these keys in the output.
	 * @param string[]                               $excl        Never include the values for these keys in the output.
	 * @param string                                 $name        The name of this target (see https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v3.x)#Variables).
	 * @param array                                  $results     Array to add output values to, will be modified by this method.
	 * @param int                                    $flags       Any of the NORMALIZE_ARRAY_* constants defined at the top of the class.
	 */
	private function normalize_array_target( $source, $only, $excl, $name, &$results, $flags = 0 ) {
		$output   = array();
		$has_only = isset( $only[0] );
		$has_excl = isset( $excl[0] );

		foreach ( $source as $source_key => $source_val ) {
			if ( is_array( $source_val ) ) {
				// if $source_val looks like a tuple from flatten_array(), then use the tuple as the key and value
				$source_key = $source_val[0];
				$source_val = $source_val[1];
			}
			$filter_match = ( $flags & self::NORMALIZE_ARRAY_MATCH_VALUES ) > 0 ? $source_val : $source_key;
			// if this key is on the "exclude" list, skip it
			if ( $has_excl && $this->key_matches( $filter_match, $excl ) ) {
				continue;
			}
			// if this key isn't in our "only" list, then skip it
			if ( $has_only && ! $this->key_matches( $filter_match, $only ) ) {
				continue;
			}
			// otherwise add this key/value to our output
			$output[] = array( $source_key, $source_val );
		}

		if ( ( $flags & self::NORMALIZE_ARRAY_COUNT ) > 0 ) {
			// If we've been told to just count the values, then just count them.
			$results[] = array(
				'name'   => (string) $name,
				'value'  => count( $output ),
				'source' => '&' . $name,
			);
		} else {
			foreach ( $output as list( $item_name, $item_value ) ) {
				$results[] = array(
					'name'   => (string) $item_name,
					'value'  => $item_value,
					'source' => "$name:$item_name",
				);
			}
		}

		return $results;
	}

	/**
	 * Given an array of tuples - probably from flatten_array() - return a new array
	 * consisting of only the first value (the key name) from each tuple.
	 *
	 * @param array{0:string, 1:scalar}[] $flat_array An array of tuples.
	 * @return string[]
	 */
	private function args_names( $flat_array ) {
		$names = array_map(
			function ( $tuple ) {
				return $tuple[0];
			},
			$flat_array
		);
		return array_unique( $names );
	}

	/**
	 * Return whether or not a given $input key matches one of the given $patterns.
	 *
	 * @param string   $input    Key name to test against patterns.
	 * @param string[] $patterns Patterns to test key name with.
	 * @return bool
	 */
	private function key_matches( $input, $patterns ) {
		foreach ( $patterns as $p ) {
			if ( '/' === $p[0] ) {
				if ( 1 === preg_match( $p, $input ) ) {
					return true;
				}
			} elseif ( 0 === strcasecmp( $p, $input ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Sanitize output generated from the request that was blocked.
	 *
	 * @param string $output Output to sanitize.
	 */
	public function sanitize_output( $output ) {
		$url_decoded_output   = rawurldecode( $output );
		$html_entities_output = htmlentities( $url_decoded_output, ENT_QUOTES, 'UTF-8' );
		// @phpcs:disable Squiz.Strings.DoubleQuoteUsage.NotRequired
		$escapers     = array( "\\", "/", "\"", "\n", "\r", "\t", "\x08", "\x0c" );
		$replacements = array( "\\\\", "\\/", "\\\"", "\\n", "\\r", "\\t", "\\f", "\\b" );
		// @phpcs:enable Squiz.Strings.DoubleQuoteUsage.NotRequired

		return( str_replace( $escapers, $replacements, $html_entities_output ) );
	}
}
