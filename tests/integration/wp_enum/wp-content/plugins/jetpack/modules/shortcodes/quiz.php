<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileNam

use Automattic\Jetpack\Assets;

/**
 * Quiz shortcode.
 *
 * Usage:
 *
 * [quiz]
 * [question]What's the right answer?[/question]
 * [wrong]This one?[explanation]Nope[/explanation][/wrong]
 * [answer]Yes, this is the one![explanation]Yay![/explanation][/answer]
 * [wrong]Maybe this one[explanation]Keep trying[/explanation][/wrong]
 * [wrong]How about this one?[explanation]Try again[/explanation][/wrong]
 * [/quiz]
 *
 * Can also be wrapped in [quiz-wrapper] to display all quizzes together.
 */
class Quiz_Shortcode {

	/**
	 * Parameters admitted by [quiz] shortcode.
	 *
	 * @since 4.5.0
	 *
	 * @var array
	 */
	private static $quiz_params = array();

	/**
	 * Whether the [quiz-wrapper] shortcode is used.
	 *
	 * @since 10.1
	 *
	 * @var bool
	 */
	private static $quiz_wrapper = false;

	/**
	 * Whether the scripts were enqueued.
	 *
	 * @since 4.5.0
	 *
	 * @var bool
	 */
	private static $scripts_enqueued = false;

	/**
	 * In a8c training, store user currently logged in.
	 *
	 * @since 4.5.0
	 *
	 * @var null
	 */
	private static $username = null;

	/**
	 * Whether the noscript tag was already printed.
	 *
	 * @since 4.5.0
	 *
	 * @var bool
	 */
	private static $noscript_info_printed = false;

	/**
	 * Whether JavaScript is available.
	 *
	 * @since 4.5.0
	 *
	 * @var null
	 */
	private static $javascript_unavailable = null;

	/**
	 * Register all shortcodes.
	 *
	 * @since 4.5.0
	 */
	public static function init() {
		add_shortcode( 'quiz-wrapper', array( __CLASS__, 'shortcode_wrapper' ) );
		add_shortcode( 'quiz', array( __CLASS__, 'shortcode' ) );
		add_shortcode( 'question', array( __CLASS__, 'question_shortcode' ) );
		add_shortcode( 'answer', array( __CLASS__, 'answer_shortcode' ) );
		add_shortcode( 'wrong', array( __CLASS__, 'wrong_shortcode' ) );
		add_shortcode( 'explanation', array( __CLASS__, 'explanation_shortcode' ) );
	}

	/**
	 * Enqueue assets needed by the quiz,
	 *
	 * @since 4.5.0
	 */
	private static function enqueue_scripts() {
		wp_enqueue_style( 'quiz', plugins_url( 'css/quiz.css', __FILE__ ), array(), JETPACK__VERSION );
		wp_enqueue_script(
			'quiz',
			Assets::get_file_url_for_environment( '_inc/build/shortcodes/js/quiz.min.js', 'modules/shortcodes/js/quiz.js' ),
			array( 'jquery' ),
			JETPACK__VERSION,
			true
		);
	}

	/**
	 * Check if this is a feed and thus JS is unavailable.
	 *
	 * @since 4.5.0
	 *
	 * @return bool|null
	 */
	private static function is_javascript_unavailable() {
		if ( self::$javascript_unavailable !== null ) {
			return self::$javascript_unavailable;
		}

		if ( is_feed() ) {
			self::$javascript_unavailable = true;
			return self::$javascript_unavailable;
		}

		self::$javascript_unavailable = false;
		return self::$javascript_unavailable;
	}

	/**
	 * Display message when JS is not available.
	 *
	 * @since 4.5.0
	 *
	 * @return string
	 */
	private static function noscript_info() {
		if ( self::$noscript_info_printed ) {
			return '';
		}
		self::$noscript_info_printed = true;
		return '<noscript><div><i>' . esc_html__( 'Please view this post in your web browser to complete the quiz.', 'jetpack' ) . '</i></div></noscript>';
	}

	/**
	 * Check if we're in WordPress.com.
	 *
	 * @since 4.5.0
	 *
	 * @return bool
	 */
	public static function is_wpcom() {
		return defined( 'IS_WPCOM' ) && IS_WPCOM;
	}

	/**
	 * Parse shortcode arguments and render its output.
	 *
	 * @since 4.5.0
	 *
	 * @param array  $atts    Shortcode parameters.
	 * @param string $content Content enclosed by shortcode tags.
	 *
	 * @return string
	 */
	public static function shortcode( $atts, $content = null ) {

		// There's nothing to do if there's nothing enclosed.
		if ( empty( $content ) ) {
			return '';
		}

		$id = '';

		if ( self::is_javascript_unavailable() ) {
			// in an e-mail print the question and the info sentence once per question, too.
			self::$noscript_info_printed = false;
		} else {

			if ( ! self::$scripts_enqueued ) {
				// lazy enqueue cannot use the wp_enqueue_scripts action anymore.
				self::enqueue_scripts();
				self::$scripts_enqueued = true;
			}

			$default_atts = self::is_wpcom()
				? array(
					'trackid'     => '',
					'a8ctraining' => '',
				)
				: array(
					'trackid' => '',
				);

			self::$quiz_params = shortcode_atts( $default_atts, $atts );

			if ( ! empty( self::$quiz_params['trackid'] ) ) {
				$id .= ' data-trackid="' . esc_attr( self::$quiz_params['trackid'] ) . '"';
			}
			if ( self::is_wpcom() && ! empty( self::$quiz_params['a8ctraining'] ) ) {
				if ( self::$username === null ) {
					self::$username = wp_get_current_user()->user_login;
				}
				$id .= ' data-a8ctraining="' . esc_attr( self::$quiz_params['a8ctraining'] ) . '" data-username="' . esc_attr( self::$username ) . '"';
			}
		}

		$quiz         = self::do_shortcode( $content );
		$quiz_options = '';

		if ( self::$quiz_wrapper ) {
			$quiz_options = '<div class="jetpack-quiz-options">
			<span class="jetpack-quiz-count"></span>
			<a class="jetpack-quiz-option-button" data-quiz-option="previous" role="button" aria-label="' . esc_attr__( 'Previous quiz', 'jetpack' ) . '">
			<svg viewBox="0 0 24 24" class="quiz-gridicon">
			<g><path d="M14 20l-8-8 8-8 1.414 1.414L8.828 12l6.586 6.586"></path></g></svg></a>
			<a class="jetpack-quiz-option-button" data-quiz-option="next" role="button" aria-label="' . esc_attr__( 'Next quiz', 'jetpack' ) . '">
			<svg viewBox="0 0 24 24" class="quiz-gridicon">
			<g><path d="M10 20l8-8-8-8-1.414 1.414L15.172 12l-6.586 6.586"></path></g></svg></a>
			</div>';
		}

		return '<div class="jetpack-quiz quiz"' . $id . '>' . $quiz . $quiz_options . '</div>';
	}

	/**
	 * Wrap shortcode contents.
	 *
	 * @since 10.1
	 *
	 * @param array  $atts    Shortcode parameters.
	 * @param string $content Content enclosed by shortcode tags.
	 *
	 * @return string
	 */
	public static function shortcode_wrapper( $atts, $content = null ) {
		self::$quiz_wrapper = true;
		return '<div class="jetpack-quiz-wrapper">' . self::do_shortcode( $content ) . '</div>';
	}

	/**
	 * Strip line breaks, restrict allowed HTML to a few allowed tags and execute nested shortcodes.
	 *
	 * @since 4.5.0
	 *
	 * @param string $content Post content.
	 *
	 * @return mixed|string
	 */
	private static function do_shortcode( $content ) {
		// strip autoinserted line breaks.
		$content = preg_replace( '#(<(?:br /|/?p)>\n?)*(\[/?[a-z]+\])(<(?:br /|/?p)>\n?)*#', '$2', $content );

		// Add internal parameter so it's only rendered when it has it.
		$content = preg_replace( '/\[(question|answer|wrong|explanation)\]/i', '[$1 quiz_item="true"]', $content );
		$content = do_shortcode( $content );
		$content = wp_kses(
			$content,
			array(
				'tt'     => array(),
				'a'      => array(
					'href'             => true,
					'class'            => true,
					'data-quiz-option' => true,
					'aria-label'       => true,
					'role'             => 'button',
				),
				'pre'    => array(),
				'strong' => array(),
				'i'      => array(),
				'svg'    => array(),
				'g'      => array(),
				'path'   => array( 'd' => true ),
				'br'     => array(),
				'span'   => array( 'class' => true ),
				'img'    => array( 'src' => true ),
				'div'    => array(
					'class'            => true,
					'data-correct'     => 1,
					'data-track-id'    => 1,
					'data-a8ctraining' => 1,
					'data-username'    => 1,
					'tabindex'         => false,
				),
			)
		);
		return $content;
	}

	/**
	 * Render question.
	 *
	 * @since 4.5.0
	 *
	 * @param array $atts    Shortcode attributes.
	 * @param null  $content Post content.
	 *
	 * @return string
	 */
	public static function question_shortcode( $atts, $content = null ) {
		return isset( $atts['quiz_item'] )
			? '<div class="jetpack-quiz-question question" tabindex="-1">' . self::do_shortcode( $content ) . '</div>'
			: '';
	}

	/**
	 * Render correct answer.
	 *
	 * @since 4.5.0
	 *
	 * @param array $atts    Shortcode attributes.
	 * @param null  $content Post content.
	 *
	 * @return string
	 */
	public static function answer_shortcode( $atts, $content = null ) {
		if ( self::is_javascript_unavailable() ) {
			return self::noscript_info();
		}

		return isset( $atts['quiz_item'] )
			? '<div class="jetpack-quiz-answer answer" data-correct="1">' . self::do_shortcode( $content ) . '</div>'
			: '';
	}

	/**
	 * Render wrong response.
	 *
	 * @since 4.5.0
	 *
	 * @param array $atts    Shortcode attributes.
	 * @param null  $content Post content.
	 *
	 * @return string
	 */
	public static function wrong_shortcode( $atts, $content = null ) {
		if ( self::is_javascript_unavailable() ) {
			return self::noscript_info();
		}

		return isset( $atts['quiz_item'] )
			? '<div class="jetpack-quiz-answer answer">' . self::do_shortcode( $content ) . '</div>'
			: '';
	}

	/**
	 * Render explanation for wrong or right answer.
	 *
	 * @since 4.5.0
	 *
	 * @param array $atts    Shortcode attributes.
	 * @param null  $content Post content.
	 *
	 * @return string
	 */
	public static function explanation_shortcode( $atts, $content = null ) {
		if ( self::is_javascript_unavailable() ) {
			return self::noscript_info();
		}

		return isset( $atts['quiz_item'] )
			? '<div class="jetpack-quiz-explanation explanation">' . self::do_shortcode( $content ) . '</div>'
			: '';
	}
}

Quiz_Shortcode::init();
