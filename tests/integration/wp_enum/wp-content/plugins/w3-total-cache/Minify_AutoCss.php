<?php
namespace W3TC;

class Minify_AutoCss {
	private $config;
	private $buffer;

	/**
	 * CSS files to ignore
	 *
	 * @var array
	 */
	private $ignore_css_files;

	/**
	 * Helper object to use
	 *
	 * @var _W3_MinifyHelpers
	 */
	private $minify_helpers;

	/**
	 * Array of processed styles
	 *
	 * @var array
	 */
	private $debug_minified_urls = array();

	/**
	 * Current position to embed minified style
	 *
	 * @var integer
	 */
	private $embed_pos;

	/**
	 * Current list of files to minify
	 *
	 * @var array
	 */
	private $files_to_minify;

	/**
	 * Current number of minification group
	 *
	 * @var integer
	 */
	private $debug = false;
	private $embed_to_html;

	/**
	 * Constructor
	 *
	 * @param unknown $config
	 * @param unknown $buffer
	 * @param unknown $minify_helpers
	 */
	function __construct( $config, $buffer, $minify_helpers ) {
		$this->config = $config;
		$this->debug = $config->get_boolean( 'minify.debug' );
		$this->buffer = $buffer;
		$this->minify_helpers = $minify_helpers;

		// ignored files
		$this->ignore_css_files = $this->config->get_array(
			'minify.reject.files.css' );
		$this->ignore_css_files = array_map( array( '\W3TC\Util_Environment',
			'normalize_file' ), $this->ignore_css_files );

		$this->embed_to_html = $this->config->get_boolean( 'minify.css.embed' );
	}

	/**
	 * Does auto-minification
	 *
	 * @return string buffer of minified content
	 */
	public function execute() {
		// find all style tags
		$buffer_nocomments = preg_replace( '~<!--.*?-->\s*~s', '', $this->buffer );
		$matches = null;

		// end of <head> means another group of styles, cannt be combined
		if ( !preg_match_all( '~((<style\s*[^>]*>.*?</style>)|(<link\s+([^>]+)/?>(.*</link>)?))~is',
				$buffer_nocomments, $matches ) ) {
			$matches = null;
		}

		if ( is_null( $matches ) ) {
			return $this->buffer;
		}

		$style_tags = $matches[1];
		$style_tags = apply_filters( 'w3tc_minify_css_style_tags',
			$style_tags );

		// pass styles
		$this->embed_pos = null;
		$this->files_to_minify = array();

		for ( $n = 0; $n < count( $style_tags ); $n++ ) {
			$this->process_style_tag( $style_tags[$n], $n );
		}

		$this->flush_collected( '' );

		return $this->buffer;
	}

	/**
	 * Returns list of minified styles
	 *
	 * @return array
	 */
	public function get_debug_minified_urls() {
		return $this->debug_minified_urls;
	}

	/**
	 * Processes style tag
	 *
	 * @param unknown $style_tag
	 * @return void
	 */
	private function process_style_tag( $style_tag, $style_tag_number ) {
		if ( $this->debug ) {
			Minify_Core::log( 'processing tag ' . substr( $style_tag, 0, 150 ) );
		}

		$tag_pos = strpos( $this->buffer, $style_tag );
		if ( $tag_pos === false ) {
			// style is external but not found, skip processing it
			if ( $this->debug ) {
				Minify_Core::log( 'style not found:' . $style_tag );
			}
			return;
		}

		$style_href = null;
		$causes_flush = true;
		if ( preg_match( '~<link\s+([^>]+)/?>(.*</link>)?~Uis', $style_tag, $match ) ) {
			// all link tags dont cause automatic flush since
			// its minified or its not style <link> tag
			$causes_flush = false;

			$attrs = array();
			$attr_matches = null;
			if ( preg_match_all( '~(\w+)=["\']([^"\']*)["\']~', $match[1],
					$attr_matches, PREG_SET_ORDER ) ) {
				foreach ( $attr_matches as $attr_match ) {
					$name = strtolower( $attr_match[1] );
					$attrs[$name] = trim( $attr_match[2] );
				}
			}

			if ( isset( $attrs['href'] ) && isset( $attrs['rel'] ) &&
				stristr( $attrs['rel'], 'stylesheet' ) !== false &&
				( !isset( $attrs['media'] ) || stristr( $attrs['media'], 'print' ) === false ) ) {
				$style_href = $attrs['href'];
			}
		}

		if ( $causes_flush ) {
			$data = array(
				'style_tag_original' => $style_tag,
				'style_tag_new' => $style_tag,
				'style_tag_number' => $style_tag_number,
				'style_tag_pos' => $tag_pos,
				'should_replace' => false,
				'buffer' => $this->buffer
			);

			$data = apply_filters( 'w3tc_minify_css_do_local_style_minification',
				$data );
			$this->buffer = $data['buffer'];

			if ( $data['should_replace'] ) {
				$this->buffer = substr_replace( $this->buffer,
					$data['style_tag_new'], $tag_pos,
					strlen( $style_tag ) );
			}

			// it's not external style, have to flush what we have before it
			if ( $this->debug ) {
				Minify_Core::log( 'its not link tag, flushing' );
			}

			$this->flush_collected( $style_tag );

			return;
		}
		if ( empty( $style_href ) ) {
			if ( $this->debug ) {
				Minify_Core::log( 'its not style link tag' );
			}
			return;
		}

		$style_href = Util_Environment::url_relative_to_full( $style_href );
		$file = Util_Environment::url_to_docroot_filename( $style_href );

		$step1_result = $this->minify_helpers->is_file_for_minification(
			$style_href, $file );
		if ( $step1_result == 'url' )
			$file = $style_href;

		$step1 = !empty( $step1_result );
		$step2 = !in_array( $file, $this->ignore_css_files );

		$do_tag_minification = $step1 && $step2;
		$do_tag_minification = apply_filters(
			'w3tc_minify_css_do_tag_minification',
			$do_tag_minification, $style_tag, $file );

		if ( !$do_tag_minification ) {
			if ( $this->debug ) {
				Minify_Core::log( 'file ' . $file .
					' didnt pass minification check:' .
					' file_for_min: ' . ( $step1 ? 'true' : 'false' ) .
					' ignore_css_files: ' . ( $step2 ? 'true' : 'false' ) );
			}

			$data = array(
				'style_tag_original' => $style_tag,
				'style_tag_new' => $style_tag,
				'style_tag_number' => $style_tag_number,
				'style_tag_pos' => $tag_pos,
				'style_href' => $style_href,
				'should_replace' => false,
				'buffer' => $this->buffer
			);

			$data = apply_filters( 'w3tc_minify_css_do_excluded_tag_style_minification',
				$data );
			$this->buffer = $data['buffer'];

			if ( $data['should_replace'] ) {
				$this->buffer = substr_replace( $this->buffer,
					$data['style_tag_new'], $tag_pos,
					strlen( $style_tag ) );
			}

			$this->flush_collected( $style_tag );
			return;
		}

		$this->debug_minified_urls[] = $file;
		$this->buffer = substr_replace( $this->buffer, '',
			$tag_pos, strlen( $style_tag ) );

		// put minified file at the place of first tag
		if ( count( $this->files_to_minify ) <= 0 )
			$this->embed_pos = $tag_pos;
		$this->files_to_minify[] = $file;

		if ( $this->config->get_string( 'minify.css.method' ) == 'minify' )
			$this->flush_collected( '' );
	}

	/**
	 * Minifies collected styles
	 */
	private function flush_collected( $last_style_tag ) {
		if ( count( $this->files_to_minify ) <= 0 )
			return;
		$do_flush_collected = apply_filters( 'w3tc_minify_css_do_flush_collected',
			true, $last_style_tag, $this );
		if ( !$do_flush_collected )
			return;

		// find embed position
		$embed_pos = $this->embed_pos;

		// build minified style tag
		$data = array(
			'files_to_minify' => $this->files_to_minify,
			'embed_pos' => $embed_pos,
			'buffer' => $this->buffer,
			'embed_to_html' => $this->embed_to_html
		);

		$data = apply_filters( 'w3tc_minify_css_step', $data );
		$this->buffer = $data['buffer'];

		if ( !empty( $data['files_to_minify'] ) ) {
			$style_data = $this->minify_helpers->generate_css_style_tag(
				$data['files_to_minify'],
				$data['embed_to_html'] );

			$data['style_to_embed_url'] = $style_data['url'];
			$data['style_to_embed_body'] = $style_data['body'];
			$data = apply_filters( 'w3tc_minify_css_step_style_to_embed',
				$data );
			$this->buffer = $data['buffer'];

			if ( $this->config->getf_boolean( 'minify.css.http2push' ) ) {
				$this->minify_helpers->http2_header_add(
					$data['style_to_embed_url'], 'style' );
			}

			// replace
			$this->buffer = substr_replace( $this->buffer,
				$data['style_to_embed_body'], $data['embed_pos'], 0 );
		}

		$this->files_to_minify = array();
	}
}
