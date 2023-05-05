<?php
/**
 * Password Checker package.
 *
 * @package  automattic/jetpack-password-checker
 */

namespace Automattic\Jetpack;

/**
 * Checks passwords strength.
 */
class Password_Checker {
	/**
	 * Minimum entropy bits a password should contain. 36 bits of entropy is considered
	 * to be a reasonable password, 28 stands for a weak one.
	 *
	 * @var int
	 */
	public $minimum_entropy_bits = 28;

	/**
	 * Test results array.
	 *
	 * @var array
	 */
	public $test_results = array();

	/**
	 * Current password score.
	 *
	 * @var int
	 */
	public $score = 0;

	/**
	 * Current multiplier affecting the score.
	 *
	 * @var int
	 */
	public $multiplier = 4;

	/**
	 * A common password disallow list, which on match will immediately disqualify the password.
	 *
	 * @var array
	 */
	public $common_passwords = array();

	/**
	 * Minimum password length setting.
	 *
	 * @var int
	 */
	public $minimum_password_length = 6;

	/**
	 * User defined strings that passwords need to be tested for a match against.
	 *
	 * @var array
	 */
	private $user_strings_to_test = array();

	/**
	 * The user object for whom the password is being tested.
	 *
	 * @var mixed
	 */
	protected $user = null;

	/**
	 * The user identifier for whom the password is being tested, used if there's no user object.
	 *
	 * @var mixed
	 */
	protected $user_id = null;

	/**
	 * Creates an instance of the password checker class for the specified user, or
	 * defaults to the currently logged in user.
	 *
	 * @param mixed $user can be an integer ID, or a WP_User object.
	 */
	public function __construct( $user = null ) {
		if ( $user === null ) {
			$this->user_id = get_current_user_id();
		} elseif ( is_object( $user ) && isset( $user->ID ) ) {
			// Existing user, using their ID.
			$this->user_id = $user->ID;
		} elseif ( is_object( $user ) ) {
			// Newly created user, using existing data.
			$this->user    = $user;
			$this->user_id = 'new_user';
		} else {
			$this->user_id = $user;
		}

		/**
		 * Filters the password strength enforcement settings.
		 *
		 * You can supply your own passwords that should not be used for authenticating in addition to weak and easy
		 * to guess strings for each user. For example, you can add passwords from known password databases to avoid
		 * compromised password usage.
		 *
		 * @param array $common_passwords strings that are forbidden for use as passwords.
		 */
		$this->common_passwords = apply_filters( 'password_checker_common_passwords', $this->common_passwords );

		/**
		 * Filters the password strength enforcement settings.
		 *
		 * You can modify the minimum password length using this filter.
		 *
		 * @param int $minimum_password_length minimum password length.
		 */
		$this->minimum_password_length = apply_filters( 'password_checker_minimum_password_length', $this->minimum_password_length );

		/**
		 * Filters the password strength enforcement settings.
		 *
		 * You can modify the minimum entropy bits requirement using this filter.
		 *
		 * @param int $minimum_entropy_bits minimum entropy bits requirement.
		 */
		$this->minimum_entropy_bits = apply_filters( 'password_checker_minimum_entropy_bits', $this->minimum_entropy_bits );
	}

	/**
	 * Run tests against a password.
	 *
	 * @param string $password      the password.
	 * @param bool   $required_only only test against required conditions, defaults to false.
	 *
	 * @return array an array containing failed and passed test results.
	 */
	public function test( $password, $required_only = false ) {
		// Run the tests.
		$results = $this->run_tests( $password, $this->get_tests(), $required_only );

		// If we've failed on the required tests, return now.
		if ( ! empty( $results['failed'] ) ) {
			return array(
				'passed'       => false,
				'test_results' => $results,
			);
		}

		$entropy_bits = $this->calculate_entropy_bits( $password );

		// If we have failed the entropy bits test, run the regex tests so we can suggest improvements.
		if ( $entropy_bits < $this->minimum_entropy_bits ) {
			$results['failed']['entropy_bits'] = $entropy_bits;
			// Run the tests.
			$results = array_merge( $results, $this->run_tests( $password, $this->get_tests( 'preg_match' ) ) );
		}

		return ( array(
			'passed'       => empty( $results['failed'] ),
			'test_results' => $results,
		) );
	}

	/**
	 * Run the tests using the currently set up object values.
	 *
	 * @param string $password      the password.
	 * @param array  $tests         tests to run.
	 * @param bool   $required_only whether to run only required tests.
	 *
	 * @return array test results.
	 */
	public function run_tests( $password, $tests, $required_only = false ) {
		$results = array(
			'passed' => array(),
			'failed' => array(),
		);

		foreach ( $tests as $test_type => $section_tests ) {
			foreach ( $section_tests as $test_name => $test_data ) {
				// Skip non-required tests if required_only param is set.
				if ( $required_only && ! $test_data['required'] ) {
					continue;
				}

				$result = call_user_func_array( array( $this, 'test_' . $test_type ), array( $password, $test_data ) );
				if ( $result ) {
					$results['passed'][] = array( 'test_name' => $test_name );
				} else {
					$results['failed'][] = array(
						'test_name'   => $test_name,
						'explanation' => $test_data['error'],
					);

					if ( isset( $test_data['fail_immediately'] ) ) {
						return $results;
					}
				}
			}
		}

		return $results;
	}

	/**
	 * Returns an array of tests that need to be run on password strings.
	 *
	 * @param array $sections only return specific sections with the passed keys, defaults to all.
	 *
	 * @return array test descriptions.
	 */
	public function get_tests( $sections = false ) {
		// Note: these should be in order of priority.
		$tests = array(
			'preg_match'      => array(
				'no_backslashes'   => array(
					'pattern'          => '/^[^\\\\]*$/u',
					'error'            => __( 'Passwords may not contain the character "\".', 'jetpack-password-checker' ),
					'required'         => true,
					'fail_immediately' => true,
				),
				'minimum_length'   => array(
					'pattern'          => '/^.{' . $this->minimum_password_length . ',}/u',
					/* translators: %d is a number of characters in the password. */
					'error'            => sprintf( __( 'Password must be at least %d characters.', 'jetpack-password-checker' ), $this->minimum_password_length ),
					'required'         => true,
					'fail_immediately' => true,
				),
				'has_mixed_case'   => array(
					'pattern'  => '/([a-z].*?[A-Z]|[A-Z].*?[a-z])/u',
					'error'    => __( 'This password is too easy to guess: you can improve it by adding additional uppercase letters, lowercase letters, or numbers.', 'jetpack-password-checker' ),
					'required' => false,
				),
				'has_digit'        => array(
					'pattern'  => '/\d/u',
					'error'    => __( 'This password is too easy to guess: you can improve it by mixing both letters and numbers.', 'jetpack-password-checker' ),
					'required' => false,
				),
				'has_special_char' => array(
					'pattern'  => '/[^a-zA-Z\d]/u',
					'error'    => __( 'This password is too easy to guess: you can improve it by including special characters such as !#=?*&.', 'jetpack-password-checker' ),
					'required' => false,
				),
			),
			'compare_to_list' => array(
				'not_a_common_password'       => array(
					'list_callback'    => 'get_common_passwords',
					'compare_callback' => 'negative_in_array',
					'error'            => __( 'This is a very common password. Choose something that will be harder for others to guess.', 'jetpack-password-checker' ),
					'required'         => true,
				),
				'not_same_as_other_user_data' => array(
					'list_callback'    => 'get_other_user_data',
					'compare_callback' => 'test_not_same_as_other_user_data',
					'error'            => __( 'Your password is too weak: Looks like you are including easy to guess information about yourself. Try something a little more unique.', 'jetpack-password-checker' ),
					'required'         => true,
				),
			),
		);

		/**
		 * Filters the password strength enforcement settings.
		 *
		 * You can determine the tests run and their order based on whatever criteria you wish to specify.
		 *
		 * @param array $tests tests to run.
		 */
		$tests = apply_filters( 'password_checker_tests', $tests );

		if ( ! $sections ) {
			return $tests;
		}

		$sections = (array) $sections;

		return array_intersect_key( $tests, array_flip( $sections ) );
	}

	/**
	 * Provides the regular expression tester functionality.
	 *
	 * @param string $password  the password.
	 * @param array  $test_data the current test data.
	 *
	 * @return bool does the test pass?
	 */
	protected function test_preg_match( $password, $test_data ) {
		return preg_match( $test_data['pattern'], $password );
	}

	/**
	 * Provides the comparison tester functionality.
	 *
	 * @param string $password  the password.
	 * @param array  $test_data the current test data.
	 *
	 * @return bool does the test pass?
	 */
	protected function test_compare_to_list( $password, $test_data ) {
		if (
			! is_callable( array( $this, $test_data['list_callback'] ) )
			|| ! is_callable( array( $this, $test_data['compare_callback'] ) )
		) {
			return false;
		}

		return call_user_func(
			array(
				$this,
				$test_data['compare_callback'],
			),
			$password,
			call_user_func( array( $this, $test_data['list_callback'] ) )
		);
	}

	/**
	 * Getter for the common password list.
	 *
	 * @return array common passwords.
	 */
	protected function get_common_passwords() {
		return $this->common_passwords;
	}

	/**
	 * Returns the widely known user data that can not be used in the password to avoid
	 * predictable strings.
	 *
	 * @return array user data.
	 */
	protected function get_other_user_data() {
		if ( empty( $this->user_id ) ) {
			return array();
		}

		$user_data = get_userdata( $this->user_id );
		if ( ! $user_data ) {
			return array();
		}

		if ( isset( $user_data->ID ) ) {
			$this->add_user_strings_to_test( get_user_meta( $user_data->ID, 'first_name', true ) );
			$this->add_user_strings_to_test( get_user_meta( $user_data->ID, 'last_name', true ) );
			$this->add_user_strings_to_test( get_user_meta( $user_data->ID, 'nickname', true ) );
		}

		if ( isset( $user_data->user_nicename ) ) {
			$this->add_user_strings_to_test( $user_data->user_nicename );
		}

		if ( isset( $user_data->display_name ) ) {
			$this->add_user_strings_to_test( $user_data->display_name );
		}

		if ( isset( $user_data->first_name ) ) {
			$this->add_user_strings_to_test( $user_data->first_name );
		}

		if ( isset( $user_data->last_name ) ) {
			$this->add_user_strings_to_test( $user_data->last_name );
		}

		if ( isset( $user_data->user_email ) ) {
			$email_username = substr( $user_data->user_email, 0, strpos( $user_data->user_email, '@' ) );
			$this->add_user_strings_to_test( $email_username, '.' );
			$this->add_user_strings_to_test( $user_data->user_email );
		}

		return $this->get_user_strings_to_test();
	}

	/**
	 * Compare the password for matches with known user data.
	 *
	 * @param string $password        the password.
	 * @param array  $strings_to_test known user data.
	 *
	 * @return bool does the test pass?
	 */
	protected function test_not_same_as_other_user_data( $password, $strings_to_test ) {
		if ( empty( $strings_to_test ) ) {
			return false;
		}

		$password_lowercase = strtolower( $password );

		foreach ( $strings_to_test as $string ) {
			$string          = strtolower( $string );
			$string_reversed = strrev( $string );

			if ( $password_lowercase === $string || $password_lowercase === $string_reversed ) {
				return false;
			}

			// Also check for the string or reversed string with any numbers just stuck to the end to catch things like bob123 as passwords.
			if (
				preg_match( '/^' . preg_quote( $string, '/' ) . '\d+$/', $password_lowercase )
				|| preg_match( '/^' . preg_quote( $string_reversed, '/' ) . '\d+$/', $password_lowercase )
			) {
				return false;
			}
		}

		return true;
	}

	/**
	 * A shorthand for the not in array construct.
	 *
	 * @param mixed $needle   the needle.
	 * @param array $haystack the haystack.
	 *
	 * @return bool is the needle not in the haystack?
	 */
	protected function negative_in_array( $needle, $haystack ) {
		return ! in_array( $needle, $haystack, true );
	}

	/**
	 * A helper function used to break a single string into its constituents so
	 * that both the full string and its constituents and any variants thereof
	 * can be tested against the password.
	 *
	 * @param string $string            the string to be broken down.
	 * @param string $explode_delimiter delimiter.
	 *
	 * @return bool
	 */
	protected function add_user_strings_to_test( $string, $explode_delimiter = ' ' ) {
		// Don't check against empty strings.
		if ( empty( $string ) ) {
			return false;
		}

		$strings = explode( $explode_delimiter, $string );

		// Remove any non alpha numeric characters from the strings to check against.
		foreach ( $strings as $key => $_string ) {
			$_string = trim( preg_replace( '/[^a-zA-Z0-9]/', '', $_string ) );
			if ( empty( $_string ) ) {
				continue;
			}

			$strings[ $key ] = $_string;
		}

		// Check the original too.
		$strings[] = trim( $string );

		// Check the original minus non alpha numeric characters.
		$strings[] = trim( preg_replace( '/[^a-zA-Z0-9]/', '', $string ) );

		// Remove any empty strings.
		// Note: This will also filter out '0'.
		$strings = array_filter( $strings );
		if ( empty( $strings ) ) {
			return false;
		}

		$this->user_strings_to_test = array_unique( array_merge( $this->user_strings_to_test, $strings ) );

		return true;
	}

	/**
	 * Getter for the user strings array.
	 *
	 * @return array user strings.
	 */
	protected function get_user_strings_to_test() {
		return $this->user_strings_to_test;
	}

	/**
	 * Return a character set size that is used in the string.
	 *
	 * @param string $password the password.
	 *
	 * @return int number of different character sets in use.
	 */
	protected function get_charset_size( $password ) {
		$size = 0;

		// Lowercase a-z.
		if ( preg_match( '/[a-z]/', $password ) ) {
			$size += 26;
		}

		// Uppercase A-Z.
		if ( preg_match( '/[A-Z]/', substr( $password, 1, - 1 ) ) ) {
			$size += 26;
		}

		// Digits.
		if ( preg_match( '/\d/', substr( $password, 1, - 1 ) ) ) {
			$size += 10;
		}

		// Over digits symbols.
		if ( preg_match( '/[!|@|#|$|%|^|&|*|(|)]/', $password ) ) {
			$size += 10;
		}

		// Other symbols.
		if ( preg_match( '#[`|~|-|_|=|+|\[|{|\]|}|\\|\|;:\'",<\.>/\?]#', $password ) ) {
			$size += 20;
		}

		// Spaces.
		if ( strpos( $password, ' ' ) ) {
			++$size;
		}

		return $size;
	}

	/**
	 * Shorthand for getting a character index.
	 *
	 * @param string $char character.
	 *
	 * @return int the character code.
	 */
	protected function get_char_index( $char ) {
		$char = strtolower( $char[0] );
		if ( $char < 'a' || $char > 'z' ) {
			return 0;
		} else {
			return ord( $char[0] ) - ord( 'a' ) + 1;
		}
	}

	/**
	 * This is the password strength calculation algorithm, based on the formula H = L(logN/log2).
	 *
	 * H = Entropy
	 * L = String length (the for iterator)
	 * N = Our charset size, via get_charset_size()
	 *
	 * @see https://en.wikipedia.org/wiki/Password_strength#Random_passwords
	 *
	 * On top of the base formula, we're also multiplying the bits of entropy for every char
	 * by 1 - (the probabily of it following the previous char)
	 * i.e.: the probablity of U following Q is ~0.84. If our password contains this pair of characters,
	 * the u char will only add ( 0.16^2 * charset_score ) to our total of entropy bits.
	 *
	 * @param string $password the password.
	 *
	 * @return float|int
	 */
	protected function calculate_entropy_bits( $password ) {
		$bits = 0;
		// Calculate the score.
		$charset_score = log( $this->get_charset_size( $password ) ) / log( 2 );

		$aidx   = $this->get_char_index( $password[0] );
		$length = strlen( $password );

		for ( $b = 1; $b < $length; $b++ ) {
			$bidx = $this->get_char_index( $password[ $b ] );

			// 27 = number of chars in the index (a-z,' ').
			$c = 1.0 - $this->frequency_table[ $aidx * 27 + $bidx ];

			// Increment the bits.
			$bits += $charset_score * $c * $c;

			// Move on to next pair.
			$aidx = $bidx;
		}

		return $bits;
	}

	/**
	 * A frequency table of character pairs, starting with  '  ' then  ' a', ' b' [...] , 'a ', 'aa' etc.
	 *
	 * @see http://rumkin.com/tools/password/passchk.php
	 *
	 * @var array
	 */
	public $frequency_table = array(
		0.23653710453418866,
		0.04577693541332556,
		0.03449832337075375,
		0.042918209651552706,
		0.037390873305146524,
		0.028509112115468728,
		0.02350896632162123,
		0.022188657238664526,
		0.028429800262428927,
		0.04357019973757107,
		0.00913602565971716,
		0.03223093745443942,
		0.02235311269864412,
		0.04438081352966905,
		0.04512377897652719,
		0.020055401662049863,
		0.055903192885260244,
		0.0024388394809739026,
		0.035207464644991984,
		0.07355941099285611,
		0.036905671380667734,
		0.026134421927394666,
		0.023787724158040528,
		0.011352092141711621,
		0.0032354570637119114,
		0.005986878553725033,
		0.008861933226417843,
		0.11511532293337222,
		0.027556203528211108,
		0.024331243621519172,
		0.039266365359381834,
		0.031599941682461,
		0.014403265782183991,
		0.015480973902901297,
		0.027770812071730572,
		0.00942761335471643,
		0.039872867764980315,
		0.0078122175244204695,
		0.02808456043154979,
		0.08429100451960927,
		0.04688963405744277,
		0.13831170724595424,
		0.002540311998833649,
		0.025211838460416972,
		0.001543082081936142,
		0.09519638431258201,
		0.061845750109345385,
		0.08907071001603732,
		0.02137571074500656,
		0.027093162268552268,
		0.005521504592506197,
		0.003023181221752442,
		0.007086747339262283,
		0.010262720513194342,
		0.08785070710016038,
		0.14617757690625455,
		0.03417291150313457,
		0.0059635515381250915,
		0.006146668610584633,
		0.195202799241872,
		0.002774748505613063,
		0.004715556203528212,
		0.0044776206444088066,
		0.11205481848665985,
		0.005654468581425864,
		0.0028820527773727946,
		0.07383000437381543,
		0.005516839189386207,
		0.006496573844583759,
		0.09843067502551392,
		0.0027140982650532145,
		0.0006893133109782768,
		0.08425368129464937,
		0.021325557661466685,
		0.006493074792243767,
		0.07023414491908442,
		0.002077270739174807,
		0.0024633328473538415,
		0.0007744569179180639,
		0.015413325557661468,
		0.0011990086018370024,
		0.13162851727657093,
		0.10115993585070711,
		0.0026989357049132527,
		0.03319317684793702,
		0.002946202070272634,
		0.0783216212275842,
		0.0018358361277154103,
		0.00258813238081353,
		0.2141688292754046,
		0.09853681294649366,
		0.0032482869222918796,
		0.04359352675317102,
		0.01993526753171016,
		0.0036880011663507797,
		0.008011663507799971,
		0.12014696019827964,
		0.0029846916460125384,
		0.0017553579238956116,
		0.029470185158186325,
		0.010413179763813967,
		0.030699518880303252,
		0.03508499781309229,
		0.002021285901734947,
		0.0010613792097973467,
		0.0005295232541186761,
		0.009677212421635807,
		0.010585799679253535,
		0.17101734946785244,
		0.07968625164018078,
		0.007839043592360402,
		0.005438693687126403,
		0.0183606939787141,
		0.2732701559994168,
		0.004953491762647616,
		0.007259367254701851,
		0.008104971570199739,
		0.13274588132380813,
		0.004210526315789474,
		0.004997813092287506,
		0.017006560723137484,
		0.007442484327161393,
		0.016789619478058026,
		0.08477737279486806,
		0.005106283714827234,
		0.0005026971861787433,
		0.04040355736987899,
		0.037535500801866156,
		0.00885960052485785,
		0.0336410555474559,
		0.007066919376002332,
		0.005344219273946639,
		0.0006333284735384167,
		0.010684939495553289,
		0.0063064586674442345,
		0.15386849394955532,
		0.015049424114302375,
		0.012162705933809595,
		0.020425134859308938,
		0.037366379938766583,
		0.02157165767604607,
		0.009373961218836564,
		0.0173214754337367,
		0.009616562181075958,
		0.029522670943286193,
		0.010154249890654615,
		0.018600962239393497,
		0.06362210234728094,
		0.03157078291296107,
		0.151603440734801,
		0.0062329785683044175,
		0.014775331681003062,
		0.0020854351946347867,
		0.1826342032366234,
		0.0878017203674005,
		0.054190989940224525,
		0.010329202507654177,
		0.012763376585508092,
		0.0064872430383437815,
		0.006381105117364048,
		0.005388540603586529,
		0.0090800408222773,
		0.09611196967487973,
		0.09940691062837148,
		0.01033969966467415,
		0.004034407348009914,
		0.008826942703017933,
		0.11474675608689314,
		0.07132584924916169,
		0.012388977985129028,
		0.005435194634786413,
		0.1417174515235457,
		0.0037066627788307337,
		0.0045802595130485495,
		0.060800699810468,
		0.005341886572386646,
		0.005683627350925791,
		0.12434932205860913,
		0.004596588423968508,
		0.0007534626038781163,
		0.07107041842834232,
		0.022361277154104096,
		0.04784720804782038,
		0.06277533168100306,
		0.003441901151771395,
		0.005828254847645429,
		0.0009669047966175828,
		0.009470768333576322,
		0.002077270739174807,
		0.12797667298440007,
		0.08797783933518005,
		0.005388540603586529,
		0.0024913252660737715,
		0.007550954949701123,
		0.2786866890217233,
		0.002509986878553725,
		0.029002478495407494,
		0.0303204548768042,
		0.07576614666861058,
		0.00246799825047383,
		0.00592389561160519,
		0.039574281965301064,
		0.00706808572678233,
		0.03304505029887739,
		0.05474150750838315,
		0.0028633911648928414,
		0.0005073625892987316,
		0.07293541332555767,
		0.053528502697186175,
		0.022566554891383584,
		0.038151334013704616,
		0.002716430966613209,
		0.005049132526607377,
		0.0009902318122175246,
		0.008997229916897508,
		0.0011861787432570347,
		0.1666377022889634,
		0.14414462749671964,
		0.003374252806531564,
		0.005169266656947077,
		0.008468873013558828,
		0.16337541915731155,
		0.002873888321912815,
		0.004305000728969237,
		0.0031141565825922144,
		0.1241172182533897,
		0.0052800699810468,
		0.008969237498177577,
		0.024094474413179766,
		0.017029887738737422,
		0.01722700102055693,
		0.10618457501093455,
		0.006147834961364631,
		0.0008269427030179326,
		0.03303571949263741,
		0.024188948826359528,
		0.05213937891820965,
		0.04505846333284735,
		0.0035270447587111824,
		0.006799825047383001,
		0.0008199445983379502,
		0.02206735675754483,
		0.001010059775477475,
		0.11971191135734072,
		0.04656538854060359,
		0.011243621519171892,
		0.06513019390581717,
		0.032375564951159064,
		0.06347047674588133,
		0.013678961947805804,
		0.03309870243475726,
		0.006982942119842543,
		0.009726199154395685,
		0.010121592068814697,
		0.032514360693978714,
		0.04986032949409535,
		0.039734072022160664,
		0.15690683773144773,
		0.03949963551538125,
		0.014790494241143023,
		0.002722262720513194,
		0.02614375273363464,
		0.10753637556495116,
		0.06764834523983088,
		0.006221315060504448,
		0.021317393206006705,
		0.0030826651115322934,
		0.002399183554454002,
		0.0019069835252952323,
		0.015595276279341012,
		0.0925126111678087,
		0.18437906400349907,
		0.006538562472663654,
		0.008719638431258201,
		0.02116693395538708,
		0.18241376293920394,
		0.007290858725761773,
		0.005976381396705059,
		0.005629975215045925,
		0.09721300481119698,
		0.004810030616707975,
		0.024303251202799244,
		0.012954658113427612,
		0.011057005394372358,
		0.02733459688001166,
		0.10135121737862662,
		0.012016912086309959,
		0.001055547455897361,
		0.009027555037177431,
		0.07162326869806095,
		0.01007143898527482,
		0.07297623560285756,
		0.006741507508383147,
		0.0036891675171307776,
		0.0008409389123778977,
		0.011272780288671819,
		0.007020265344802449,
		0.1030389269572824,
		0.15350809155853623,
		0.004232686980609419,
		0.004353987461729115,
		0.0023385333138941536,
		0.14450386353695874,
		0.002546143752733635,
		0.0024470039364338824,
		0.01200758128006998,
		0.0981227584195947,
		0.003161976964572095,
		0.040695145064878264,
		0.03460446129173349,
		0.003908441463770229,
		0.01598483743986004,
		0.13107216795451232,
		0.003129319142732177,
		0.00032307916605919226,
		0.04050386353695874,
		0.05452689896486368,
		0.03589677795597026,
		0.07087097244496282,
		0.006143169558244642,
		0.008684647907858289,
		0.0004607085580988482,
		0.022010205569324977,
		0.0009097536083977258,
		0.07328765126111678,
		0.14751421490013122,
		0.008015162560139961,
		0.006601545414783497,
		0.025279486805656802,
		0.1682449336637994,
		0.008313748359819215,
		0.007010934538562473,
		0.005886572386645284,
		0.16889575739903775,
		0.004123050007289692,
		0.011925936725470185,
		0.10007289692374982,
		0.013380376148126549,
		0.009021723283277445,
		0.08650823735238372,
		0.007756232686980609,
		0.0007243038343781893,
		0.0026791077416533026,
		0.02797492345823006,
		0.032384895757399036,
		0.04187432570345531,
		0.00882461000145794,
		0.0032401224668318998,
		0.00033357632307916605,
		0.027878116343490307,
		0.0022277299897944304,
		0.14333518005540166,
		0.1725534334451086,
		0.02781629975215046,
		0.006909462020702727,
		0.005264907420906838,
		0.16661437527336345,
		0.004325995043009185,
		0.003334596880011664,
		0.005312727802886718,
		0.14024668318996938,
		0.0013261408368566844,
		0.003504884093891238,
		0.006375273363464061,
		0.04964922000291588,
		0.008290421344219274,
		0.09536783787724158,
		0.05394372357486515,
		0.005505175681586237,
		0.005339553870826651,
		0.01782067356757545,
		0.006710016037323225,
		0.05105933809593235,
		0.002983525295232541,
		0.002940370316372649,
		0.0004548768041988629,
		0.01208456043154979,
		0.000915585362297711,
		0.20146260387811635,
		0.067196967487972,
		0.006158332118384605,
		0.025438110511736407,
		0.07753783350342616,
		0.1273876658405015,
		0.009337804344656656,
		0.07683452398308792,
		0.0070412596588423975,
		0.08747164309666132,
		0.0038827817466102928,
		0.018116926665694706,
		0.005017641055547455,
		0.004567429654468581,
		0.028277008310249308,
		0.05271555620352821,
		0.004394809739029013,
		0.0013343052923166642,
		0.00411605190260971,
		0.059621519171890944,
		0.09073859163143316,
		0.01446858142586383,
		0.006770666277883074,
		0.003425572240851436,
		0.0004455459979588861,
		0.010401516256013998,
		0.005825922146085436,
		0.10833882490158916,
		0.007584779122321038,
		0.016903921854497742,
		0.02719580113719201,
		0.0304814112844438,
		0.02206385770520484,
		0.013064295086747339,
		0.02696369733197259,
		0.009581571657676046,
		0.026761918647033093,
		0.006510570053943724,
		0.021941390873305145,
		0.07042659279778393,
		0.05437410701268406,
		0.1425175681586237,
		0.027802303542790494,
		0.037690625455605774,
		0.0019606356611750987,
		0.1095623268698061,
		0.06157748942994606,
		0.044618749088788455,
		0.04955124653739612,
		0.03608689313310978,
		0.018381688292754043,
		0.003404577926811489,
		0.015036594255722409,
		0.009600233270156,
		0.10794693103951014,
		0.12447528794284882,
		0.0031981338387520046,
		0.0074716430966613205,
		0.003202799241871993,
		0.13437643971424407,
		0.006655197550663361,
		0.0036693395538708266,
		0.049338970695436656,
		0.09486863974340283,
		0.0015990669193760023,
		0.0026604461291733486,
		0.051775477474850555,
		0.0041347135150896636,
		0.005450357194926374,
		0.12030325120279925,
		0.04581309228750547,
		0.0004537104534188657,
		0.12425601399620935,
		0.025981629975215047,
		0.023926519900860182,
		0.04423385333138941,
		0.0017950138504155123,
		0.002661612479953346,
		0.0006333284735384167,
		0.008449045050298877,
		0.000653156436798367,
		0.04816678816153958,
		0.008625164018078437,
		0.0039037760606502403,
		0.005228750546726928,
		0.004531272780288672,
		0.0056672984400058316,
		0.00359585945473101,
		0.0032179618020119548,
		0.0038093016474704767,
		0.011452398308791368,
		0.002519317684793702,
		0.00280390727511299,
		0.005572824026826068,
		0.004554599795888614,
		0.004531272780288672,
		0.0035841959469310393,
		0.004400641492928998,
		0.0036670068523108326,
		0.004839189386207902,
		0.006258638285464354,
		0.004897506925207757,
		0.840776789619478,
		0.004968654322787578,
		0.002886718180492783,
		0.0019757982213150604,
		0.0018568304417553576,
		0.001691208630995772,
		0.09009243329931477,
		0.14030150167662925,
		0.013242746756086894,
		0.013746610293045632,
		0.027342761335471644,
		0.16938912377897652,
		0.006607377168683481,
		0.01661933226417845,
		0.008173786266219566,
		0.13297448607668758,
		0.0034675608689313307,
		0.016641492928998396,
		0.011722991689750693,
		0.021493512173786266,
		0.03430820819361423,
		0.10099548039072752,
		0.00873596734217816,
		0.0018323370753754193,
		0.020103222044029742,
		0.047197550663362,
		0.040833940807697915,
		0.03361189677795597,
		0.010844729552412887,
		0.005544831608106138,
		0.0007522962530981193,
		0.01525120279924187,
		0.00815512465373961,
		0.2109648636827526,
		0.058258055110074355,
		0.007181221752442048,
		0.043560868931331105,
		0.004058900714389853,
		0.10618107595859454,
		0.0062399766729844,
		0.004835690333867911,
		0.02679224376731302,
		0.08414637702288964,
		0.0030698352529523252,
		0.03637498177576906,
		0.01592885260242018,
		0.017413617145356466,
		0.008430383437818923,
		0.037231083248286924,
		0.03290275550371775,
		0.007538125091121154,
		0.004500947660008748,
		0.05932409972299169,
		0.16006764834523984,
		0.03309636973319726,
		0.007766729844000583,
		0.005225251494386936,
		0.0006321621227584196,
		0.012989648636827526,
		0.005274238227146815,
		0.1254503571949264,
		0.12852719055255868,
		0.0035433736696311416,
		0.005203090829566993,
		0.0019314768916751715,
		0.20520775623268697,
		0.002509986878553725,
		0.00343606939787141,
		0.027138649948972155,
		0.13926578218399185,
		0.004565096952908587,
		0.005614812654905963,
		0.00874413179763814,
		0.004109053797929727,
		0.008300918501239247,
		0.08270943286193323,
		0.002912377897652719,
		0.0037066627788307337,
		0.06909578655780726,
		0.03242805073625893,
		0.05237614812654906,
		0.04723487388832191,
		0.0038991106575302524,
		0.006299460562764251,
		0.00043388249015891526,
		0.020029741944889927,
		0.005311561452106721,
		0.09334072022160665,
		0.022940953491762648,
		0.024658988190698353,
		0.02901297565242747,
		0.03531593526753171,
		0.0758023035427905,
		0.013711619769645722,
		0.021597317393206007,
		0.009670214316955824,
		0.044728386062108175,
		0.010596296836273509,
		0.03264382563055839,
		0.0604822860475288,
		0.05489546581134276,
		0.11501851581863246,
		0.01837585653885406,
		0.026237060796034405,
		0.0011255285026971862,
		0.08704125965884241,
		0.10156349322058608,
		0.06660562764251349,
		0.023434319871701415,
		0.010777081207173057,
		0.005409534917626476,
		0.003123487388832191,
		0.0028762210234728096,
		0.0089995626184575,
		0.07518297127861205,
		0.2314868056568013,
		0.002226563639014434,
		0.003285610147251786,
		0.0027455897361131363,
		0.2724537104534189,
		0.0016655489138358362,
		0.0019209797346551977,
		0.0022137337804344656,
		0.17690392185449774,
		0.0014532730718763668,
		0.0024994897215337513,
		0.015302522233561744,
		0.003441901151771395,
		0.015303688584341741,
		0.09314593964134713,
		0.0017833503426155418,
		0.0005108616416387229,
		0.017828838023035427,
		0.010385187345094037,
		0.003168975069252078,
		0.01902901297565243,
		0.005525003644846187,
		0.0010088934246974776,
		0.0009272488700976819,
		0.036282840064149294,
		0.0022977110365942554,
		0.0766805656801283,
		0.22270418428342326,
		0.005283569033386791,
		0.007155562035282111,
		0.01173582154833066,
		0.1715620352821111,
		0.003925936725470185,
		0.004425134859308937,
		0.020040239101909902,
		0.14243242455168392,
		0.0016737133692958156,
		0.0066808572678232975,
		0.011980755212130047,
		0.012638577052048404,
		0.07206065024055984,
		0.08115701997375711,
		0.00710424260096224,
		0.0007278028867181805,
		0.02347630849978131,
		0.04595538708266512,
		0.01481965301064295,
		0.013925061962385188,
		0.0018125091121154687,
		0.00529173348884677,
		0.0016340574427759146,
		0.03072401224668319,
		0.0023746901880740633,
		0.25174165330223064,
		0.06673392622831317,
		0.00878378772415804,
		0.03956261845750109,
		0.010077270739174807,
		0.0844787869951888,
		0.00985216503863537,
		0.004973319725907567,
		0.01893220586091267,
		0.11200583175389998,
		0.0028715556203528212,
		0.004095057588569762,
		0.01202391019098994,
		0.01756757544831608,
		0.014825484764542934,
		0.05312961073042717,
		0.06746872721971132,
		0.003845458521650386,
		0.0210806239976673,
		0.019443067502551394,
		0.08017028721387957,
		0.01825572240851436,
		0.005365213587986587,
		0.01959702580551101,
		0.026184575010934536,
		0.02474879720075813,
		0.002171745152354571,
		0.25827321767021433,
		0.048050153083539875,
		0.01043184137629392,
		0.03930485493512174,
		0.027640180784370902,
		0.03294007872867765,
		0.006474413179763814,
		0.018314039947514214,
		0.015119405161102202,
		0.014706516984983233,
		0.005494678524566263,
		0.03309870243475726,
		0.043864120134130345,
		0.058996355153812505,
		0.06265986295378335,
		0.04633328473538417,
		0.03790756670068523,
		0.0004642076104388394,
		0.037849249161685375,
		0.08369966467415076,
		0.04999679253535501,
		0.02392768625164018,
		0.010998687855372504,
		0.009881323808135296,
		0.003867619186470331,
		0.012434465665548913,
		0.007253535500801866,
		0.11106225397288234,
		0.17624726636535937,
		0.008209943140399476,
		0.008390727511299025,
		0.012682898381688294,
		0.1825653885406036,
		0.001538416678816154,
		0.004590756670068524,
		0.008710307625018223,
		0.1299513048549351,
		0.002677941390873305,
		0.012309666132089225,
		0.014087184720804781,
		0.01199941682461,
		0.031246537396121883,
		0.07206648199445984,
		0.008254264470039366,
		0.0007033095203382417,
		0.007034261554162415,
		0.006599212713223502,
		0.013906400349905234,
		0.050098265053214755,
		0.007133401370462167,
		0.017750692520775622,
		0.0008257763522379356,
		0.03918821985712203,
		0.06015454147834961,
	);
}
