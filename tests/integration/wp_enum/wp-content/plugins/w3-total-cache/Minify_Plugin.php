<?php
namespace W3TC;

/**
 * class Minify_Plugin
 */
class Minify_Plugin {
	/**
	 * Minify reject reason
	 *
	 * @var string
	 */
	var $minify_reject_reason = '';

	/**
	 * Error
	 *
	 * @var string
	 */
	var $error = '';

	/**
	 * Array of replaced styles
	 *
	 * @var array
	 */
	var $replaced_styles = array();

	/**
	 * Array of replaced scripts
	 *
	 * @var array
	 */
	var $replaced_scripts = array();

	/**
	 * Helper object to use
	 *
	 * @var _W3_MinifyHelpers
	 */
	private $minify_helpers;

	/**
	 * Config
	 */
	private $_config = null;

	function __construct() {
		$this->_config = Dispatcher::config();
	}

	/**
	 * Runs plugin
	 */
	function run() {
		add_action( 'init', array( $this, 'init' ) );
		add_filter( 'cron_schedules', array( $this, 'cron_schedules' ) );

		add_filter( 'w3tc_admin_bar_menu',
			array( $this, 'w3tc_admin_bar_menu' ) );

		add_filter( 'w3tc_footer_comment', array(
				$this, 'w3tc_footer_comment' ) );

		if ( $this->_config->get_string( 'minify.engine' ) == 'file' ) {
			add_action( 'w3_minify_cleanup', array(
					$this,
					'cleanup'
				) );
		}
		add_filter( 'w3tc_pagecache_set_header',
			array( $this, 'w3tc_pagecache_set_header' ), 20, 2 );

		// usage statistics handling
		add_action( 'w3tc_usage_statistics_of_request', array(
				$this, 'w3tc_usage_statistics_of_request' ), 10, 1 );
		add_filter( 'w3tc_usage_statistics_metrics', array(
				$this, 'w3tc_usage_statistics_metrics' ) );

		/**
		 * Start minify
		 */
		if ( $this->can_minify() ) {
			Util_Bus::add_ob_callback( 'minify', array( $this, 'ob_callback' ) );
		}
	}

	public function init() {
		$url = Util_Environment::filename_to_url( W3TC_CACHE_MINIFY_DIR );
		$parsed = parse_url( $url );
		$prefix = '/' . trim( $parsed['path'], '/' ) . '/';

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( substr( $request_uri, 0, strlen( $prefix ) ) == $prefix ) {
			$w3_minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
			$filename = Util_Environment::remove_query_all( substr( $request_uri, strlen( $prefix ) ) );
			$w3_minify->process( $filename );
			exit();
		}

		if ( !empty( Util_Request::get_string( 'w3tc_minify' ) ) ) {
			$w3_minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
			$w3_minify->process( Util_Request::get_string( 'w3tc_minify' ) );
			exit();
		}
	}

	/**
	 * Does disk cache cleanup
	 *
	 * @return void
	 */
	function cleanup() {
		$a = Dispatcher::component( 'Minify_Plugin_Admin' );
		$a->cleanup();
	}

	/**
	 * Cron schedules filter
	 *
	 * @param array   $schedules
	 * @return array
	 */
	function cron_schedules( $schedules ) {
		$gc = $this->_config->get_integer( 'minify.file.gc' );

		return array_merge( $schedules, array(
				'w3_minify_cleanup' => array(
					'interval' => $gc,
					'display' => sprintf( '[W3TC] Minify file GC (every %d seconds)', $gc )
				)
			) );
	}

	/**
	 * OB callback
	 *
	 * @param string  $buffer
	 * @return string
	 */
	function ob_callback( $buffer ) {
		$enable = Util_Content::is_html( $buffer ) &&
			$this->can_minify2( $buffer );
		$enable = apply_filters( 'w3tc_minify_enable', $enable );
		if ( !$enable )
			return $buffer;


		$this->minify_helpers = new _W3_MinifyHelpers( $this->_config );

		/**
		 * Replace script and style tags
		 */
		$js_enable = $this->_config->get_boolean( 'minify.js.enable' );
		$css_enable = $this->_config->get_boolean( 'minify.css.enable' );
		$html_enable = $this->_config->get_boolean( 'minify.html.enable' );

		if ( function_exists( 'is_feed' ) && is_feed() ) {
			$js_enable = false;
			$css_enable = false;
		}

		$js_enable = apply_filters( 'w3tc_minify_js_enable', $js_enable );
		$css_enable = apply_filters( 'w3tc_minify_css_enable', $css_enable );
		$html_enable = apply_filters( 'w3tc_minify_html_enable', $html_enable );

		$head_prepend = '';
		$body_prepend = '';
		$body_append = '';
		$embed_extsrcjs = false;
		$buffer = apply_filters( 'w3tc_minify_before', $buffer );



		if ( $this->_config->get_boolean( 'minify.auto' ) ) {
			if ( $js_enable ) {
				$minifier = new Minify_AutoJs( $this->_config,
					$buffer, $this->minify_helpers );
				$buffer = $minifier->execute();
				$this->replaced_scripts =
					$minifier->get_debug_minified_urls();
			}

			if ( $css_enable ) {
				$minifier = new Minify_AutoCss( $this->_config, $buffer,
					$this->minify_helpers );
				$buffer = $minifier->execute();
			}

			$buffer = apply_filters( 'w3tc_minify_processed', $buffer );
		} else {
			if ( $css_enable ) {
				$style = $this->get_style_group( 'include' );

				if ( $style['body'] ) {
					if ( $this->_custom_location_does_not_exist( '/<!-- W3TC-include-css -->/', $buffer, $style['body'] ) )
						$head_prepend .= $style['body'];

					$this->remove_styles_group( $buffer, 'include' );
				}

				if ( $this->_config->getf_boolean( 'minify.css.http2push' ) ) {
					$this->minify_helpers->http2_header_add( $style['url'],
						'style' );
				}
			}

			if ( $js_enable ) {
				$embed_type = $this->_config->get_string( 'minify.js.header.embed_type' );
				$http2push = $this->_config->getf_boolean( 'minify.js.http2push' );

				$script = $this->get_script_group( 'include', $embed_type );

				if ( $script['body'] ) {
					$embed_extsrcjs = $embed_type == 'extsrc' || $embed_type == 'asyncsrc'?true:$embed_extsrcjs;

					if ( $this->_custom_location_does_not_exist( '/<!-- W3TC-include-js-head -->/', $buffer, $script['body'] ) )
						$head_prepend .= $script['body'];

					$this->remove_scripts_group( $buffer, 'include' );
				}
				if ( $http2push ) {
					$this->minify_helpers->http2_header_add( $script['url'],
						'script' );
				}

				$embed_type = $this->_config->get_string( 'minify.js.body.embed_type' );
				$script = $this->get_script_group( 'include-body', $embed_type );

				if ( $script['body'] ) {
					$embed_extsrcjs = $embed_type == 'extsrc' || $embed_type == 'asyncsrc'?true:$embed_extsrcjs;

					if ( $this->_custom_location_does_not_exist( '/<!-- W3TC-include-js-body-start -->/', $buffer, $script['body'] ) )
						$body_prepend .= $script['body'];

					$this->remove_scripts_group( $buffer, 'include-body' );
				}
				if ( $http2push ) {
					$this->minify_helpers->http2_header_add( $script['url'],
						'script' );
				}

				$embed_type = $this->_config->get_string( 'minify.js.footer.embed_type' );
				$script = $this->get_script_group( 'include-footer', $embed_type );

				if ( $script['body'] ) {
					$embed_extsrcjs = $embed_type == 'extsrc' || $embed_type == 'asyncsrc'?true:$embed_extsrcjs;

					if ( $this->_custom_location_does_not_exist( '/<!-- W3TC-include-js-body-end -->/', $buffer, $script['body'] ) )
						$body_append .= $script['body'];

					$this->remove_scripts_group( $buffer, 'include-footer' );
				}
				if ( $http2push ) {
					$this->minify_helpers->http2_header_add( $script['url'],
						'script' );
				}
			}
		}

		if ( $head_prepend != '' ) {
			$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui',
				'\\0' . $head_prepend, $buffer, 1 );
		}

		if ( $body_prepend != '' ) {
			$buffer = preg_replace( '~<body(\s+[^>]*)*>~Ui',
				'\\0' . $body_prepend, $buffer, 1 );
		}

		if ( $body_append != '' ) {
			$buffer = preg_replace( '~<\\/body>~',
				$body_append . '\\0', $buffer, 1 );
		}

		if ( $embed_extsrcjs ) {
			$script = "
<script>
" ."var extsrc=null;
".'(function(){function j(){if(b&&g){document.write=k;document.writeln=l;var f=document.createElement("span");f.innerHTML=b;g.appendChild(f);b=""}}function d(){j();for(var f=document.getElementsByTagName("script"),c=0;c<f.length;c++){var e=f[c],h=e.getAttribute("asyncsrc");if(h){e.setAttribute("asyncsrc","");var a=document.createElement("script");a.async=!0;a.src=h;document.getElementsByTagName("head")[0].appendChild(a)}if(h=e.getAttribute("extsrc")){e.setAttribute("extsrc","");g=document.createElement("span");e.parentNode.insertBefore(g,e);document.write=function(a){b+=a};document.writeln=function(a){b+=a;b+="\n"};a=document.createElement("script");a.async=!0;a.src=h;/msie/i.test(navigator.userAgent)&&!/opera/i.test(navigator.userAgent)?a.onreadystatechange=function(){("loaded"==this.readyState||"complete"==this.readyState)&&d()}:-1!=navigator.userAgent.indexOf("Firefox")||"onerror"in a?(a.onload=d,a.onerror=d):(a.onload=d,a.onreadystatechange=d);document.getElementsByTagName("head")[0].appendChild(a);return}}j();document.write=k;document.writeln=l;for(c=0;c<extsrc.complete.funcs.length;c++)extsrc.complete.funcs[c]()}function i(){arguments.callee.done||(arguments.callee.done=!0,d())}extsrc={complete:function(b){this.complete.funcs.push(b)}};extsrc.complete.funcs=[];var k=document.write,l=document.writeln,b="",g="";document.addEventListener&&document.addEventListener("DOMContentLoaded",i,!1);if(/WebKit/i.test(navigator.userAgent))var m=setInterval(function(){/loaded|complete/.test(document.readyState)&&(clearInterval(m),i())},10);window.onload=i})();' . "
</script>
";

			$buffer = preg_replace( '~<head(\s+[^>]*)*>~Ui',
				'\\0' . $script, $buffer, 1 );
		}

		/**
		 * Minify HTML/Feed
		 */
		if ( $html_enable ) {
			try {
				$buffer = $this->minify_html( $buffer );
			} catch ( \Exception $exception ) {
				$this->error = $exception->getMessage();
			}
		}

		return $buffer;
	}

	public function w3tc_admin_bar_menu( $menu_items ) {
		$menu_items['20210.minify'] = array(
			'id' => 'w3tc_flush_minify',
			'parent' => 'w3tc_flush',
			'title' => __( 'Minify', 'w3-total-cache' ),
			'href' => wp_nonce_url( admin_url(
					'admin.php?page=w3tc_dashboard&amp;w3tc_flush_minify' ),
				'w3tc' )
		);

		return $menu_items;
	}

	function w3tc_footer_comment( $strings ) {
		$strings[] = sprintf(
			__( 'Minified using %s%s', 'w3-total-cache' ),
			Cache::engine_name( $this->_config->get_string( 'minify.engine' ) ),
			( $this->minify_reject_reason != ''
				? sprintf( ' (%s)', $this->minify_reject_reason )
				: '' ) );

		if ( $this->_config->get_boolean( 'minify.debug' ) ) {
			$strings[] = '';
			$strings[] = 'Minify debug info:';
			$strings[] = sprintf( "%s%s", str_pad( 'Theme: ', 20 ), $this->get_theme() );
			$strings[] = sprintf( "%s%s", str_pad( 'Template: ', 20 ), $this->get_template() );

			if ( $this->error ) {
				$strings[] = sprintf( "%s%s", str_pad( 'Errors: ', 20 ), $this->error );
			}

			if ( count( $this->replaced_styles ) ) {
				$strings[] = 'Replaced CSS files:';

				foreach ( $this->replaced_styles as $index => $file ) {
					$strings[] = sprintf( "%d. %s", $index + 1, Util_Content::escape_comment( $file ) );
				}
			}

			if ( count( $this->replaced_scripts ) ) {
				$strings[] = 'Replaced JavaScript files:';

				foreach ( $this->replaced_scripts as $index => $file ) {
					$strings[] = sprintf( "%d. %s\r\n", $index + 1, Util_Content::escape_comment( $file ) );
				}
			}
			$strings[] = '';
		}

		return $strings;
	}
	/**
	 * Checks to see if pattern exists in source if so replaces it with the provided script
	 * and returns false. If pattern does not exists returns true.
	 *
	 * @param unknown $pattern
	 * @param unknown $source
	 * @param unknown $script
	 * @return bool
	 */
	function _custom_location_does_not_exist( $pattern, &$source, $script ) {
		$count = 0;
		$source = preg_replace( $pattern, $script, $source, 1, $count );
		return $count==0;
	}

	/**
	 * Removes style tags from the source
	 *
	 * @param string  $content
	 * @param array   $files
	 * @return void
	 */
	function remove_styles( &$content, $files ) {
		$regexps = array();
		$home_url_regexp = Util_Environment::home_url_regexp();

		$path = '';
		if ( Util_Environment::is_wpmu() && !Util_Environment::is_wpmu_subdomain() )
			$path = ltrim( Util_Environment::home_url_uri(), '/' );

		foreach ( $files as $file ) {
			if ( $path && strpos( $file, $path ) === 0 )
				$file = substr( $file, strlen( $path ) );

			$this->replaced_styles[] = $file;

			if ( Util_Environment::is_url( $file ) && !preg_match( '~' . $home_url_regexp . '~i', $file ) ) {
				// external CSS files
				$regexps[] = Util_Environment::preg_quote( $file );
			} else {
				// local CSS files
				$file = ltrim( $file, '/' );
				if ( home_url() == site_url() && ltrim( Util_Environment::site_url_uri(), '/' ) && strpos( $file, ltrim( Util_Environment::site_url_uri(), '/' ) ) === 0 )
					$file = str_replace( ltrim( Util_Environment::site_url_uri(), '/' ), '', $file );
				$file = ltrim( preg_replace( '~' . $home_url_regexp . '~i', '', $file ), '/\\' );
				$regexps[] = '(' . $home_url_regexp . ')?/?' . Util_Environment::preg_quote( $file );
			}
		}

		foreach ( $regexps as $regexp ) {
			$content = preg_replace( '~<link\s+[^<>]*href=["\']?' . $regexp . '["\']?[^<>]*/?>(.*</link>)?~Uis', '', $content );
			$content = preg_replace( '~@import\s+(url\s*)?\(?["\']?\s*' . $regexp . '\s*["\']?\)?[^;]*;?~is', '', $content );
		}

		$content = preg_replace( '~<style[^<>]*>\s*</style>~', '', $content );
	}

	/**
	 * Remove script tags from the source
	 *
	 * @param string  $content
	 * @param array   $files
	 * @return void
	 */
	function remove_scripts( &$content, $files ) {
		$regexps = array();
		$home_url_regexp = Util_Environment::home_url_regexp();

		$path = '';
		if ( Util_Environment::is_wpmu() && !Util_Environment::is_wpmu_subdomain() ) {
			$path = ltrim( Util_Environment::network_home_url_uri(), '/' );
		}

		foreach ( $files as $file ) {
			if ( $path && strpos( $file, $path ) === 0 ) {
				$file = substr( $file, strlen( $path ) );
			}

			$this->replaced_scripts[] = $file;

			if ( Util_Environment::is_url( $file ) && !preg_match( '~' . $home_url_regexp . '~i', $file ) ) {
				// external JS files
				$regexps[] = Util_Environment::preg_quote( $file );
			} else {
				// local JS files
				$file = ltrim( $file, '/' );
				if ( home_url() == site_url() &&
						ltrim( Util_Environment::site_url_uri(), '/' ) &&
						strpos( $file, ltrim( Util_Environment::site_url_uri(), '/' ) ) === 0 ) {
					$file = str_replace( ltrim( Util_Environment::site_url_uri(), '/' ), '', $file );
				}

				$file = ltrim( preg_replace( '~' . $home_url_regexp . '~i', '', $file ), '/\\' );
				$regexps[] = '(' . $home_url_regexp . ')?/?' . Util_Environment::preg_quote( $file );
			}
		}

		foreach ( $regexps as $regexp ) {
			$content = preg_replace( '~<script\s+[^<>]*src=["\']?' . $regexp . '["\']?[^<>]*>\s*</script>~Uis', '', $content );
		}
	}

	/**
	 * Removes style tag from the source for group
	 *
	 * @param string  $content
	 * @param string  $location
	 * @return void
	 */
	function remove_styles_group( &$content, $location ) {
		$theme = $this->get_theme();
		$template = $this->get_template();

		$files = array();
		$groups = $this->_config->get_array( 'minify.css.groups' );

		if ( isset( $groups[$theme]['default'][$location]['files'] ) ) {
			$files = (array) $groups[$theme]['default'][$location]['files'];
		}

		if ( $template != 'default' && isset( $groups[$theme][$template][$location]['files'] ) ) {
			$files = array_merge( $files, (array) $groups[$theme][$template][$location]['files'] );
		}

		$this->remove_styles( $content, $files );
	}

	/**
	 * Removes script tags from the source for group
	 *
	 * @param string  $content
	 * @param string  $location
	 * @return void
	 */
	function remove_scripts_group( &$content, $location ) {
		$theme = $this->get_theme();
		$template = $this->get_template();
		$files = array();
		$groups = $this->_config->get_array( 'minify.js.groups' );

		if ( isset( $groups[$theme]['default'][$location]['files'] ) ) {
			$files = (array) $groups[$theme]['default'][$location]['files'];
		}

		if ( $template != 'default' && isset( $groups[$theme][$template][$location]['files'] ) ) {
			$files = array_merge( $files, (array) $groups[$theme][$template][$location]['files'] );
		}

		$this->remove_scripts( $content, $files );
	}

	/**
	 * Minifies HTML
	 *
	 * @param string  $html
	 * @return string
	 */
	function minify_html( $html ) {
		$w3_minifier = Dispatcher::component( 'Minify_ContentMinifier' );

		$ignored_comments = $this->_config->get_array( 'minify.html.comments.ignore' );

		if ( count( $ignored_comments ) ) {
			$ignored_comments_preserver = new \W3TCL\Minify\Minify_IgnoredCommentPreserver();
			$ignored_comments_preserver->setIgnoredComments( $ignored_comments );

			$html = $ignored_comments_preserver->search( $html );
		}

		if ( $this->_config->get_boolean( 'minify.html.inline.js' ) ) {
			$js_engine = $this->_config->get_string( 'minify.js.engine' );

			if ( !$w3_minifier->exists( $js_engine ) || !$w3_minifier->available( $js_engine ) ) {
				$js_engine = 'js';
			}

			$js_minifier = $w3_minifier->get_minifier( $js_engine );
			$js_options = $w3_minifier->get_options( $js_engine );

			$w3_minifier->init( $js_engine );

			$html = \W3TCL\Minify\Minify_Inline_JavaScript::minify( $html, $js_minifier, $js_options );
		}

		if ( $this->_config->get_boolean( 'minify.html.inline.css' ) ) {
			$css_engine = $this->_config->get_string( 'minify.css.engine' );

			if ( !$w3_minifier->exists( $css_engine ) || !$w3_minifier->available( $css_engine ) ) {
				$css_engine = 'css';
			}

			$css_minifier = $w3_minifier->get_minifier( $css_engine );
			$css_options = $w3_minifier->get_options( $css_engine );

			$w3_minifier->init( $css_engine );

			$html = \W3TCL\Minify\Minify_Inline_CSS::minify( $html, $css_minifier, $css_options );
		}

		$engine = $this->_config->get_string( 'minify.html.engine' );

		if ( !$w3_minifier->exists( $engine ) || !$w3_minifier->available( $engine ) ) {
			$engine = 'html';
		}

		if ( function_exists( 'is_feed' ) && is_feed() ) {
			$engine .= 'xml';
		}

		$minifier = $w3_minifier->get_minifier( $engine );
		$options = $w3_minifier->get_options( $engine );

		$w3_minifier->init( $engine );

		$html = call_user_func( $minifier, $html, $options );

		if ( isset( $ignored_comments_preserver ) ) {
			$html = $ignored_comments_preserver->replace( $html );
		}

		return $html;
	}

	/**
	 * Returns current theme
	 *
	 * @return string
	 */
	function get_theme() {
		static $theme = null;

		if ( $theme === null ) {
			$theme = Util_Theme::get_theme_key( get_theme_root(), get_template(), get_stylesheet() );
		}

		return $theme;
	}

	/**
	 * Returns current template
	 *
	 * @return string
	 */
	function get_template() {
		static $template = null;

		if ( $template === null ) {
			$template_file = 'index.php';
			switch ( true ) {
			case ( is_404() && ( $template_file = get_404_template() ) ):
			case ( is_search() && ( $template_file = get_search_template() ) ):
			case ( is_tax() && ( $template_file = get_taxonomy_template() ) ):
			case ( is_front_page() && function_exists( 'get_front_page_template' ) && $template_file = get_front_page_template() ):
			case ( is_home() && ( $template_file = get_home_template() ) ):
			case ( is_attachment() && ( $template_file = get_attachment_template() ) ):
			case ( is_single() && ( $template_file = get_single_template() ) ):
			case ( is_page() && ( $template_file = get_page_template() ) ):
			case ( is_category() && ( $template_file = get_category_template() ) ):
			case ( is_tag() && ( $template_file = get_tag_template() ) ):
			case ( is_author() && ( $template_file = get_author_template() ) ):
			case ( is_date() && ( $template_file = get_date_template() ) ):
			case ( is_archive() && ( $template_file = get_archive_template() ) ):
			case ( is_paged() && ( $template_file = get_paged_template() ) ):
				break;

			default:
				if ( function_exists( 'get_index_template' ) ) {
					$template_file = get_index_template();
				} else {
					$template_file = 'index.php';
				}
				break;
			}

			$template = basename( $template_file, '.php' );
		}

		return $template;
	}

	/**
	 * Returns style tag
	 *
	 * @param string  $url
	 * @param boolean $import
	 * @param boolean $use_style
	 * @return string
	 */
	function get_style( $url, $import = false, $use_style = true ) {
		if ( $import && $use_style ) {
			return "<style media=\"all\">@import url(\"" . $url . "\");</style>\r\n";
		} elseif ( $import && !$use_style ) {
			return "@import url(\"" . $url . "\");\r\n";
		}else {
			return "<link rel=\"stylesheet\" href=\"" . str_replace( '&', '&amp;', $url ) . "\" media=\"all\" />\r\n";
		}
	}

	/**
	 * Returns style tag for style group
	 *
	 * @param string  $location
	 * @return array
	 */
	function get_style_group( $location ) {
		$style = false;
		$type = 'css';
		$groups = $this->_config->get_array( 'minify.css.groups' );
		$theme = $this->get_theme();
		$template = $this->get_template();

		if ( $template != 'default' && empty( $groups[$theme][$template][$location]['files'] ) ) {
			$template = 'default';
		}

		$return = array(
			'url' => null,
			'body' => ''
		);

		if ( !empty( $groups[$theme][$template][$location]['files'] ) ) {
			if ( $this->_config->get_boolean( 'minify.css.embed' ) ) {
				$minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
				$minify_filename = $this->get_minify_manual_filename(
					$theme, $template, $location, $type );

				$m = $minify->process( $minify_filename, true );
				if ( isset( $m['content'] ) )
					$style = $m['content'];
				else
					$style = 'not set';

				$return['body'] = "<style media=\"all\">$style</style>\r\n";
			} else {
				$return['url'] = $this->get_minify_manual_url( $theme, $template, $location, $type );

				if ( $return['url'] ) {
					$import = ( isset( $groups[$theme][$template][$location]['import'] ) ? (boolean) $groups[$theme][$template][$location]['import'] : false );

					$return['body'] = $this->get_style( $return['url'], $import );
				}
			}
		}

		return $return;
	}

	/**
	 * Returns script tag for script group
	 *
	 * @param string  $location
	 * @param string  $embed_type
	 * @return array
	 */
	function get_script_group( $location, $embed_type = 'blocking' ) {
		$script = false;
		$fileType = 'js';
		$theme = $this->get_theme();
		$template = $this->get_template();
		$groups = $this->_config->get_array( 'minify.js.groups' );

		if ( $template != 'default' && empty( $groups[$theme][$template][$location]['files'] ) ) {
			$template = 'default';
		}

		$return = array(
			'url' => null,
			'body' => ''
		);

		if ( !empty( $groups[$theme][$template][$location]['files'] ) ) {
			$return['url'] = $this->get_minify_manual_url( $theme, $template, $location, $fileType );

			if ( $return['url'] ) {
				$return['body'] = $this->minify_helpers->generate_script_tag(
					$return['url'], $embed_type );
			}
		}

		return $return;
	}

	/**
	 * Returns style tag for custom files
	 *
	 * @return string
	 */
	function get_style_custom( $files, $embed_to_html = false ) {
		return $this->minify_helpers->generate_css_style_tag(
			$files, $embed_to_html );
	}

	/**
	 * Generates filename for minify manual resource
	 */
	function get_minify_manual_filename( $theme, $template, $location, $type ) {
		$minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
		$id = $minify->get_id_group( $theme, $template, $location, $type );
		if ( !$id )
			return false;

		return $theme . '.' . $template . '.' . $location . '.'. $id .
			'.' . $type;
	}

	/**
	 * Generates URL for minify manual resource
	 */
	function get_minify_manual_url( $theme, $template, $location, $type ) {
		return Minify_Core::minified_url( $this->get_minify_manual_filename(
			$theme, $template, $location, $type ) );
	}

	/**
	 * Returns array of minify URLs
	 *
	 * @return array
	 */
	function get_urls() {
		$files = array();

		$js_groups = $this->_config->get_array( 'minify.js.groups' );
		$css_groups = $this->_config->get_array( 'minify.css.groups' );

		foreach ( $js_groups as $js_theme => $js_templates ) {
			foreach ( $js_templates as $js_template => $js_locations ) {
				foreach ( (array) $js_locations as $js_location => $js_config ) {
					if ( !empty( $js_config['files'] ) ) {
						$files[] = $this->get_minify_manual_url( $js_theme, $js_template, $js_location, 'js' );
					}
				}
			}
		}

		foreach ( $css_groups as $css_theme => $css_templates ) {
			foreach ( $css_templates as $css_template => $css_locations ) {
				foreach ( (array) $css_locations as $css_location => $css_config ) {
					if ( !empty( $css_config['files'] ) ) {
						$files[] = $this->get_minify_manual_url( $css_theme, $css_template, $css_location, 'css' );
					}
				}
			}
		}

		return $files;
	}

	/**
	 * Check if we can do minify logic
	 *
	 * @return boolean
	 */
	function can_minify() {
		/**
		 * Skip if doint AJAX
		 */
		if ( defined( 'DOING_AJAX' ) ) {
			$this->minify_reject_reason = 'Doing AJAX';

			return false;
		}

		/**
		 * Skip if doing cron
		 */
		if ( defined( 'DOING_CRON' ) ) {
			$this->minify_reject_reason = 'Doing cron';

			return false;
		}

		/**
		 * Skip if APP request
		 */
		if ( defined( 'APP_REQUEST' ) ) {
			$this->minify_reject_reason = 'Application request';

			return false;
		}

		/**
		 * Skip if XMLRPC request
		 */
		if ( defined( 'XMLRPC_REQUEST' ) ) {
			$this->minify_reject_reason = 'XMLRPC request';

			return false;
		}

		/**
		 * Skip if Admin
		 */
		if ( defined( 'WP_ADMIN' ) ) {
			$this->minify_reject_reason = 'wp-admin';

			return false;
		}

		/**
		 * Check for WPMU's and WP's 3.0 short init
		 */
		if ( defined( 'SHORTINIT' ) && SHORTINIT ) {
			$this->minify_reject_reason = 'Short init';

			return false;
		}

		/**
		 * Check User agent
		 */
		if ( !$this->check_ua() ) {
			$this->minify_reject_reason = 'User agent is rejected';

			return false;
		}

		/**
		 * Check request URI
		 */
		if ( !$this->check_request_uri() ) {
			$this->minify_reject_reason = 'Request URI is rejected';

			return false;
		}

		/**
		 * Skip if user is logged in
		 */
		if ( $this->_config->get_boolean( 'minify.reject.logged' ) && !$this->check_logged_in() ) {
			$this->minify_reject_reason = 'User is logged in';

			return false;
		}

		return true;
	}

	/**
	 * Returns true if we can minify
	 *
	 * @param string  $buffer
	 * @return string
	 */
	function can_minify2( $buffer ) {
		/**
		 * Check for DONOTMINIFY constant
		 */
		if ( defined( 'DONOTMINIFY' ) && DONOTMINIFY ) {
			$this->minify_reject_reason = 'DONOTMINIFY constant is defined';

			return false;
		}

		/**
		 * Check feed minify
		 */
		if ( $this->_config->get_boolean( 'minify.html.reject.feed' ) && function_exists( 'is_feed' ) && is_feed() ) {
			$this->minify_reject_reason = 'Feed is rejected';

			return false;
		}

		return true;
	}

	/**
	 * Checks User Agent
	 *
	 * @return boolean
	 */
	function check_ua() {
		$uas = array_merge( $this->_config->get_array( 'minify.reject.ua' ), array(
				W3TC_POWERED_BY
			) );

		foreach ( $uas as $ua ) {
			if ( !empty( $ua ) ) {
				if ( stristr( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', $ua ) !== false ) {
					return false;
				}
			}
		}

		return true;
	}

	/**
	 * Check if user is logged in
	 *
	 * @return boolean
	 */
	function check_logged_in() {
		foreach ( array_keys( $_COOKIE ) as $cookie_name ) {
			if ( strpos( $cookie_name, 'wordpress_logged_in' ) === 0 )
				return false;
		}

		return true;
	}

	/**
	 * Checks request URI
	 *
	 * @return boolean
	 */
	function check_request_uri() {
		$auto_reject_uri = array(
			'wp-login',
			'wp-register'
		);

		foreach ( $auto_reject_uri as $uri ) {
			if ( strstr( isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '', $uri ) !== false ) {
				return false;
			}
		}

		$reject_uri = $this->_config->get_array( 'minify.reject.uri' );
		$reject_uri = array_map( array( '\W3TC\Util_Environment', 'parse_path' ), $reject_uri );

		foreach ( $reject_uri as $expr ) {
			$expr = trim( $expr );
			$expr = str_replace( '~', '\~', $expr );

			if ( '' !== $expr && preg_match( '~' . $expr . '~i', isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' ) ) {
				return false;
			}
		}

		if ( Util_Request::get_string( 'wp_customize' ) )
			return false;

		return true;
	}



	public function w3tc_usage_statistics_of_request( $storage ) {
		$o = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );
		$o->w3tc_usage_statistics_of_request( $storage );
	}



	public function w3tc_usage_statistics_metrics( $metrics ) {
		return array_merge( $metrics, array(
				'minify_requests_total',
				'minify_original_length_css', 'minify_output_length_css',
				'minify_original_length_js', 'minify_output_length_js', ) );
	}



	public function w3tc_pagecache_set_header( $header, $header_original ) {
		if ( $header_original['n'] == 'Link' &&
				false !== strpos( $header_original['v'], 'rel=preload' ) ) {
			// store preload Link headers in cache
			$new = $header_original;
			$new['files_match'] = '\\.html[_a-z]*$';
			return $new;
		}

		return $header;
	}
}



class _W3_MinifyHelpers {
	/**
	 * Config
	 */
	private $config;
	private $debug = false;

	/**
	 * Constructor
	 *
	 * @param W3_COnfig $config
	 */
	function __construct( $config ) {
		$this->config = $config;
		$this->debug = $config->get_boolean( 'minify.debug' );
	}

	/**
	 * Formats custom URL
	 *
	 * @param array   $files
	 * @param string  $type
	 * @return array
	 */
	function get_minify_url_for_files( $files, $type ) {
		$minify_filename =
			Minify_Core::urls_for_minification_to_minify_filename(
			$files, $type );
		if ( is_null( $minify_filename ) )
			return null;

		$url = Minify_Core::minified_url( $minify_filename );
		$url = Util_Environment::url_to_maybe_https( $url );

		$url = apply_filters( 'w3tc_minify_url_for_files', $url, $files, $type );

		return $url;
	}

	/**
	 * Returns minified content
	 *
	 * @param array   $files
	 * @param string  $type
	 * @return array
	 */
	function get_minified_content_for_files( $files, $type ) {
		$minify_filename =
			Minify_Core::urls_for_minification_to_minify_filename(
			$files, $type );
		if ( is_null( $minify_filename ) )
			return null;
		$minify = Dispatcher::component( 'Minify_MinifiedFileRequestHandler' );

		$m = $minify->process( $minify_filename, true );
		if ( !isset( $m['content'] ) )
			return null;
		if ( empty( $m['content'] ) )
			return null;

		$style = $m['content'];
		return "<style media=\"all\">$style</style>\r\n";
	}

	/**
	 * Prints script tag
	 *
	 * @param string  $url
	 * @param string  $embed_type
	 * @return string
	 */
	function generate_script_tag( $url, $embed_type = 'blocking' ) {
		static $non_blocking_function = false;

		$rocket_loader_ignore = "";
		if( $this->config->get_boolean( array( 'cloudflare', 'minify_js_rl_exclude' ) ) ){
			$rocket_loader_ignore = 'data-cfasync="false"';
		}

		if ( $embed_type == 'blocking' ) {
			$script = '<script ' . $rocket_loader_ignore . ' src="' .
				str_replace( '&', '&amp;', $url ) . '"></script>';
		} else {
			$script = '';

			if ( $embed_type == 'nb-js' ) {
				if ( !$non_blocking_function ) {
					$non_blocking_function = true;
					$script = "<script>function w3tc_load_js(u){var d=document,p=d.getElementsByTagName('HEAD')[0],c=d.createElement('script');c.src=u;p.appendChild(c);}</script>";
				}

				$script .= "<script>w3tc_load_js('" .
					$url . "');</script>";

			} elseif ( $embed_type == 'nb-async' ) {
				$script = '<script ' . $rocket_loader_ignore . ' async src="' .
					str_replace( '&', '&amp;', $url ) . '"></script>';
			} elseif ( $embed_type == 'nb-defer' ) {
				$script = '<script ' . $rocket_loader_ignore . ' defer src="' .
					str_replace( '&', '&amp;', $url ) . '"></script>';
			} elseif ( $embed_type == 'extsrc' ) {
				$script = '<script ' . $rocket_loader_ignore . ' extsrc="' .
					str_replace( '&', '&amp;', $url ) . '"></script>';
			} elseif ( $embed_type == 'asyncsrc' ) {
				$script = '<script ' . $rocket_loader_ignore . ' asyncsrc="' .
					str_replace( '&', '&amp;', $url ) . '"></script>';
			} else {
				$script = '<script ' . $rocket_loader_ignore . ' src="' .
					str_replace( '&', '&amp;', $url ) . '"></script>';
			}
		}

		return $script . "\r\n";
	}

	/**
	 * URL file filter
	 *
	 * @param string  $file
	 * @return bool
	 */
	public function is_file_for_minification( $url, $file ) {
		static $external;
		static $external_regexp;
		if ( !isset( $external ) ) {
			$external = $this->config->get_array( 'minify.cache.files' );
			$external_regexp = $this->config->get_boolean( 'minify.cache.files_regexp' );
		}

		foreach ( $external as $item ) {
			if ( empty( $item ) )
				continue;

			if ( $external_regexp ) {
				$item = str_replace( '~', '\~', $item );
				if ( ! preg_match( '~' . $item . '~', $url ) )
					continue;
			} else {
				if ( ! preg_match( '~^' . Util_Environment::get_url_regexp( $item ) . '~', $url ) )
					continue;
			}

			if ( $this->debug ) {
				Minify_Core::log(
					'is_file_for_minification: whilelisted ' . $url . ' by ' . $item );
			}

			return 'url';
		}


		if ( is_null( $file ) ) {
			if ( $this->debug ) {
				Minify_Core::log(
					'is_file_for_minification: external not whitelisted url ' . $url );
			}

			return '';
		}

		$file_normalized = Util_Environment::remove_query_all( $file );
		$ext = strrchr( $file_normalized, '.' );

		if ( $ext != '.js' && $ext != '.css' ) {
			if ( $this->debug ) {
				Minify_Core::log(
					'is_file_for_minification: unknown extension ' . $ext .
					' for ' . $file );
			}

			return '';
		}

		$path = Util_Environment::docroot_to_full_filename( $file );

		if ( !file_exists( $path ) ) {
			if ( $this->debug ) {
				Minify_Core::log(
					'is_file_for_minification: file doesnt exists ' . $path );
			}

			return '';
		}

		if ( $this->debug ) {
			Minify_Core::log(
				'is_file_for_minification: true for file ' . $file .
				' path ' . $path );
		}

		return 'file';
	}

	/**
	 * Sends HTTP/2 push header
	 */
	public function http2_header_add( $url, $as ) {
		if ( empty( $url ) )
			return;

		// Cloudflare needs URI without host
		$uri = Util_Environment::url_to_uri( $url );

		// priorities attached:
		// 3000 - cdn
		// 4000 - browsercache
		$data = apply_filters( 'w3tc_minify_http2_preload_url', array(
			'result_link' => $uri,
			'original_url' => $url
		) );

		header( 'Link: <' . $data['result_link'] . '>; rel=preload; as=' . $as, false );
	}



	function generate_css_style_tag( $files, $embed_to_html ) {
		$return = array(
			'url' => null,
			'body' => ''
		);

		if ( count( $files ) ) {
			if ( $embed_to_html ) {
				$body = $this->get_minified_content_for_files(
					$files, 'css' );
				if ( !is_null( $body ) ) {
					$return['body'] = $body;
				}
			}

			if ( empty( $return['body'] ) ) {
				$return['url'] = $this->get_minify_url_for_files(
					$files, 'css' );
				if ( !is_null( $return['url'] ) ) {
					$return['body'] =
						"<link rel=\"stylesheet\" href=\"" .
						str_replace( '&', '&amp;', $return['url'] ) .
						"\" media=\"all\" />\r\n";
				}
			}
		}

		return $return;
	}
}
