<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
use Automattic\Jetpack\VideoPress\Jwt_Token_Bridge;

/**
 * VideoPress playback module markup generator.
 *
 * @since 1.3
 */
class VideoPress_Player {
	/**
	 * Video data for the requested guid and maximum width
	 *
	 * @since 1.3
	 * @var VideoPress_Video
	 */
	protected $video;

	/**
	 * DOM identifier of the video container
	 *
	 * @var string
	 * @since 1.3
	 */
	protected $video_container_id;

	/**
	 * DOM identifier of the video element (video, object, embed)
	 *
	 * @var string
	 * @since 1.3
	 */
	protected $video_id;

	/**
	 * Array of playback options: force_flash or freedom
	 *
	 * @var array
	 * @since 1.3
	 */
	protected $options;

	/**
	 * Array of video GUIDs shown and their counts,
	 * moved from the old VideoPress class.
	 *
	 * @var array
	 */
	public static $shown = array();

	/**
	 * Initiate a player object based on shortcode values and possible blog-level option overrides
	 *
	 * @since 1.3
	 * @param string $guid VideoPress unique identifier.
	 * @param int    $maxwidth Maximum desired width of the video player if specified.
	 * @param array  $options Player customizations.
	 */
	public function __construct( $guid, $maxwidth = 0, $options = array() ) {
		if ( empty( self::$shown[ $guid ] ) ) {
			self::$shown[ $guid ] = 0;
		}

		++self::$shown[ $guid ];

		$this->video_container_id = 'v-' . $guid . '-' . self::$shown[ $guid ];
		$this->video_id           = $this->video_container_id . '-video';

		if ( is_array( $options ) ) {
			$this->options = $options;
		} else {
			$this->options = array();
		}

		// set up the video
		$cache_key = null;

		// disable cache in debug mode
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG === true ) {
			$cached_video = null;
		} else {
			$cache_key_pieces = array( 'video' );

			if ( is_multisite() && is_subdomain_install() ) {
				$cache_key_pieces[] = get_current_blog_id();
			}

			$cache_key_pieces[] = $guid;
			if ( $maxwidth > 0 ) {
				$cache_key_pieces[] = $maxwidth;
			}
			if ( is_ssl() ) {
				$cache_key_pieces[] = 'ssl';
			}
			$cache_key = implode( '-', $cache_key_pieces );
			unset( $cache_key_pieces );
			$cached_video = wp_cache_get( $cache_key, 'video' );
		}
		if ( empty( $cached_video ) ) {
			$video = new VideoPress_Video( $guid, $maxwidth );
			if ( empty( $video ) ) {
				return;
			} elseif ( isset( $video->error ) ) {
				$this->video = $video->error;
				return;
			} elseif ( is_wp_error( $video ) ) {
				$this->video = $video;
				return;
			}

			$this->video = $video;
			unset( $video );

			if ( ! defined( 'WP_DEBUG' ) || WP_DEBUG !== true ) {
				$expire = 3600;
				if ( isset( $this->video->expires ) && is_int( $this->video->expires ) ) {
					$expires_diff = time() - $this->video->expires;
					if ( $expires_diff > 0 && $expires_diff < 86400 ) { // allowed range: 1 second to 1 day
						$expire = $expires_diff;
					}
					unset( $expires_diff );
				}

				wp_cache_set( $cache_key, serialize( $this->video ), 'video', $expire ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize
				unset( $expire );
			}
		} else {
			$this->video = unserialize( $cached_video ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- Make sure to unserialize as VideoPress_Video class.
		}
		unset( $cache_key );
		unset( $cached_video );
	}

	/**
	 * Wrap output in a VideoPress player container.
	 *
	 * @since 1.3
	 * @param string $content HTML string.
	 * @return string HTML string or blank string if nothing to wrap.
	 */
	private function html_wrapper( $content ) {
		if ( empty( $content ) ) {
			return '';
		} else {
			return '<div id="' . esc_attr( $this->video_container_id ) . '" class="video-player">' . $content . '</div>';
		}
	}

	/**
	 * Output content suitable for a feed reader displaying RSS or Atom feeds
	 * We do not display error messages in the feed view due to caching concerns.
	 * Flash content presented using <embed> markup for feed reader compatibility.
	 *
	 * @since 1.3
	 * @return string HTML string or empty string if error
	 */
	public function as_xml() {
		if ( empty( $this->video ) || is_wp_error( $this->video ) ) {
			return '';
		}

		if ( isset( $this->options['force_flash'] ) && true === $this->options['force_flash'] ) {
			$content = $this->flash_embed();

		} else {
			$content = $this->html5_static();
		}

		return $this->html_wrapper( $content );
	}

	/**
	 * Video player markup for best matching the current request and publisher options
	 *
	 * @since 1.3
	 * @return string HTML markup string or empty string if no video property found
	 */
	public function as_html() {
		if ( empty( $this->video ) ) {
			$content = '';

		} elseif ( is_wp_error( $this->video ) ) {
			$content = $this->error_message( $this->video );

		} elseif ( isset( $this->options['force_flash'] ) && true === $this->options['force_flash'] ) {
			$content = $this->flash_object();

		} elseif ( isset( $this->video->restricted_embed ) && true === $this->video->restricted_embed ) {

			if ( $this->options['forcestatic'] ) {
				$content = $this->flash_object();

			} else {
				$content = $this->html5_dynamic();
			}
		} elseif ( isset( $this->options['freedom'] ) && true === $this->options['freedom'] ) {
			$content = $this->html5_static();

		} else {
			$content = $this->html5_dynamic();
		}

		return $this->html_wrapper( $content );
	}

	/**
	 * Display an error message to users capable of doing something about the error
	 *
	 * @since 1.3
	 * @uses current_user_can() to test if current user has edit_posts capability.
	 * @param WP_Error $error WordPress error.
	 * @return string HTML string
	 */
	private function error_message( $error ) {
		if ( ! current_user_can( 'edit_posts' ) || empty( $error ) ) {
			return '';
		}

		$html = '<div class="videopress-error" style="background-color:rgb(255,0,0);color:rgb(255,255,255);font-family:font-family:\'Helvetica Neue\',Arial,Helvetica,\'Nimbus Sans L\',sans-serif;font-size:140%;min-height:10em;padding-top:1.5em;padding-bottom:1.5em">';
		/* translators: %s is 'VideoPress' */
		$html .= '<h1 style="font-size:180%;font-style:bold;line-height:130%;text-decoration:underline">' . esc_html( sprintf( __( '%s Error', 'jetpack' ), 'VideoPress' ) ) . '</h1>';
		foreach ( $error->get_error_messages() as $message ) {
			$html .= $message;
		}
		$html .= '</div>';
		return $html;
	}

	/**
	 * Rating agencies and industry associations require a potential viewer verify their age before a video or its poster frame are displayed.
	 * Content rated for audiences 17 years of age or older requires such verification across multiple rating agencies and industry associations
	 *
	 * @since 1.3
	 * @return bool true if video requires the viewer verify they are 17 years of age or older
	 */
	private function age_gate_required() {
		if ( isset( $this->video->age_rating ) && $this->video->age_rating >= 17 ) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Select a date of birth using HTML form elements.
	 *
	 * @since 1.5
	 * @return string HTML markup
	 */
	private function html_age_gate() {
		global $wp_locale;
		$text_align = 'left';
		if ( $this->video->text_direction === 'rtl' ) {
			$text_align = 'right';
		}

		$html         = '<div class="videopress-age-gate" style="margin:0 60px">';
		$html        .= '<p class="instructions" style="color:rgb(255, 255, 255);font-size:21px;padding-top:60px;padding-bottom:20px;text-align:' . $text_align . '">' . esc_html( __( 'This video is intended for mature audiences.', 'jetpack' ) ) . '<br />' . esc_html( __( 'Please verify your birthday.', 'jetpack' ) ) . '</p>';
		$html        .= '<fieldset id="birthday" style="border:0 none;text-align:' . $text_align . ';padding:0;">';
		$inputs_style = 'border:1px solid #444;margin-';
		if ( $this->video->text_direction === 'rtl' ) {
			$inputs_style .= 'left';
		} else {
			$inputs_style .= 'right';
		}
		$inputs_style .= ':10px;background-color:rgb(0, 0, 0);font-size:14px;color:rgb(255,255,255);padding:4px 6px;line-height: 2em;vertical-align: middle';

		/**
		 * Display a list of months in the Gregorian calendar.
		 * Set values to 0-based to match JavaScript Date.
		 *
		 * @link https://developer.mozilla.org/en/JavaScript/Reference/global_objects/date Mozilla JavaScript Reference: Date
		 */
		$html .= '<select name="month" style="' . $inputs_style . '">';

		for ( $i = 0; $i < 12; $i++ ) {
			$html .= '<option value="' . esc_attr( $i ) . '">' . esc_html( $wp_locale->get_month( $i + 1 ) ) . '</option>';
		}
		$html .= '</select>';

		/**
		 * Todo: numdays variance by month.
		 */
		$html .= '<select name="day" style="' . $inputs_style . '">';
		for ( $i = 1; $i < 32; $i++ ) {
			$html .= '<option>' . $i . '</option>';
		}
		$html .= '</select>';

		/**
		 * Current record for human life is 122. Go back 130 years and no one is left out.
		 * Don't ask infants younger than 2 for their birthday
		 * Default to 13
		 */
		$html        .= '<select name="year" style="' . $inputs_style . '">';
		$start_year   = gmdate( 'Y' ) - 2;
		$default_year = $start_year - 11;
		$end_year     = $start_year - 128;
		for ( $year = $start_year; $year > $end_year; $year-- ) {
			$html .= '<option';
			if ( $year === $default_year ) {
				$html .= ' selected="selected"';
			}
			$html .= '>' . $year . '</option>';
		}
		unset( $start_year );
		unset( $default_year );
		unset( $end_year );
		$html .= '</select>';

		$html .= '<input type="submit" value="' . __( 'Submit', 'jetpack' ) . '" style="cursor:pointer;border-radius: 1em;border:1px solid #333;background-color:#333;background:-webkit-gradient( linear, left top, left bottom, color-stop(0.0, #444), color-stop(1, #111) );background:-moz-linear-gradient(center top, #444 0%, #111 100%);font-size:13px;padding:4px 10px 5px;line-height:1em;vertical-align:top;color:white;text-decoration:none;margin:0" />';

		$html .= '</fieldset>';
		$html .= '<p style="padding-top:20px;padding-bottom:60px;text-align:' . $text_align . ';"><a rel="nofollow noopener noreferrer" href="https://videopress.com/" target="_blank" style="color:rgb(128,128,128);text-decoration:underline;font-size:15px">' . __( 'More information', 'jetpack' ) . '</a></p>';

		$html .= '</div>';
		return $html;
	}

	/**
	 * Return HTML5 video static markup for the given video parameters.
	 * Use default browser player controls.
	 * No Flash fallback.
	 *
	 * @since 1.2
	 * @link https://html.spec.whatwg.org/multipage/media.html#the-video-element HTML5 video
	 * @return string HTML5 video element and children
	 */
	private function html5_static() {
		wp_enqueue_script( 'videopress' );
		$thumbnail = esc_url( $this->video->poster_frame_uri );
		$html      = "<video id=\"{$this->video_id}\" width=\"{$this->video->calculated_width}\" height=\"{$this->video->calculated_height}\" poster=\"$thumbnail\" controls=\"true\"";
		if ( isset( $this->options['autoplay'] ) && $this->options['autoplay'] === true ) {
			$html .= ' autoplay="true"';
		} else {
			$html .= ' preload="' . $this->options['preloadContent'] . '"';
		}
		if ( isset( $this->video->text_direction ) ) {
			$html .= ' dir="' . esc_attr( $this->video->text_direction ) . '"';
		}
		if ( isset( $this->video->language ) ) {
			$html .= ' lang="' . esc_attr( $this->video->language ) . '"';
		}
		$html .= '>';
		if (
			( ! isset( $this->options['freedom'] ) || $this->options['freedom'] === false )
			&& isset( $this->video->videos->mp4 )
		) {
			$mp4 = $this->video->videos->mp4->url;
			if ( ! empty( $mp4 ) ) {
				$html .= '<source src="' . esc_url( $mp4 ) . '" type="video/mp4; codecs=&quot;' . esc_attr( $this->video->videos->mp4->codecs ) . '&quot;" />';
			}
			unset( $mp4 );
		}

		if ( isset( $this->video->videos->ogv ) ) {
			$ogg = $this->video->videos->ogv->url;
			if ( ! empty( $ogg ) ) {
				$html .= '<source src="' . esc_url( $ogg ) . '" type="video/ogg; codecs=&quot;' . esc_attr( $this->video->videos->ogv->codecs ) . '&quot;" />';
			}

			unset( $ogg );
		}

		$html .= '<div><img alt="';
		if ( isset( $this->video->title ) ) {
			$html .= esc_attr( $this->video->title );
		}
		$html .= '" src="' . $thumbnail . '" width="' . $this->video->calculated_width . '" height="' . $this->video->calculated_height . '" /></div>';
		if ( isset( $this->options['freedom'] ) && $this->options['freedom'] === true ) {
			/* translators: %s url to the gnu.org website */
			$html .= '<p class="robots-nocontent">' . sprintf( __( 'You do not have sufficient <a rel="nofollow noopener noreferrer" href="%s" target="_blank">freedom levels</a> to view this video. Support free software and upgrade.', 'jetpack' ), 'https://www.gnu.org/philosophy/free-sw.html' ) . '</p>';
		} elseif ( isset( $this->video->title ) ) {
			$html .= '<p>' . esc_html( $this->video->title ) . '</p>';
		}
		$html .= '</video>';
		return $html;
	}

	/**
	 * Click to play dynamic HTML5-capable player.
	 * The player displays a video preview section including poster frame,
	 * video title, play button and watermark on the original page load
	 * and calculates the playback capabilities of the browser. The video player
	 * is loaded when the visitor clicks on the video preview area.
	 * If Flash Player 10 or above is available the browser will display
	 * the Flash version of the video. If HTML5 video appears to be supported
	 * and the browser may be capable of MP4 (H.264, AAC) or OGV (Theora, Vorbis)
	 * playback the browser will display its native HTML5 player.
	 *
	 * @since 1.5
	 * @return string HTML markup
	 */
	private function html5_dynamic() {

		/**
		 * Filter the VideoPress legacy player feature
		 *
		 * This filter allows you to control whether the legacy VideoPress player should be used
		 * instead of the improved one.
		 *
		 * @module videopress
		 *
		 * @since 3.7.0
		 *
		 * @param boolean $videopress_use_legacy_player
		 */
		if ( ! apply_filters( 'jetpack_videopress_use_legacy_player', false ) ) {
			return $this->html5_dynamic_next();
		}

		wp_enqueue_script( 'videopress' );
		$video_placeholder_id = $this->video_container_id . '-placeholder';
		$age_gate_required    = $this->age_gate_required();
		$width                = absint( $this->video->calculated_width );
		$height               = absint( $this->video->calculated_height );

		$html = '<div id="' . $video_placeholder_id . '" class="videopress-placeholder" style="';
		if ( $age_gate_required ) {
			$html .= "min-width:{$width}px;min-height:{$height}px";
		} else {
			$html .= "width:{$width}px;height:{$height}px";
		}
		$html .= ';display:none;cursor:pointer !important;position:relative;';
		if ( isset( $this->video->skin ) && isset( $this->video->skin->background_color ) ) {
			$html .= 'background-color:' . esc_attr( $this->video->skin->background_color ) . ';';
		}
		$html .= 'font-family: \'Helvetica Neue\',Arial,Helvetica,\'Nimbus Sans L\',sans-serif;font-weight:bold;font-size:18px">' . PHP_EOL;

		/**
		 * Do not display a poster frame, title, or any other content hints for mature content.
		 */
		if ( ! $age_gate_required ) {
			if ( ! empty( $this->video->title ) ) {
				$html .= '<div class="videopress-title" style="display:inline;position:absolute;margin:20px 20px 0 20px;padding:4px 8px;vertical-align:top;text-align:';
				if ( $this->video->text_direction === 'rtl' ) {
					$html .= 'right" dir="rtl"';
				} else {
					$html .= 'left" dir="ltr"';
				}
				if ( isset( $this->video->language ) ) {
					$html .= ' lang="' . esc_attr( $this->video->language ) . '"';
				}
				$html .= '><span style="padding:3px 0;line-height:1.5em;';
				if ( isset( $this->video->skin ) && isset( $this->video->skin->background_color ) ) {
					$html .= 'background-color:';
					if ( $this->video->skin->background_color === 'rgb(0,0,0)' ) {
						$html .= 'rgba(0,0,0,0.8)';
					} else {
						$html .= esc_attr( $this->video->skin->background_color );
					}
					$html .= ';';
				}
				$html .= 'color:rgb(255,255,255)">' . esc_html( $this->video->title ) . '</span></div>';
			}
			$html .= '<img class="videopress-poster" alt="';
			if ( ! empty( $this->video->title ) ) {
				/* translators: %s is the video title */
				$html .= esc_attr( $this->video->title ) . '" title="' . esc_attr( sprintf( _x( 'Watch: %s', 'watch a video title', 'jetpack' ), $this->video->title ) );
			}
			$html .= '" src="' . esc_url( $this->video->poster_frame_uri, array( 'http', 'https' ) ) . '" width="' . $width . '" height="' . $height . '" />' . PHP_EOL;

			// style a play button hovered over the poster frame
			$html .= '<div class="play-button"><span style="z-index:2;display:block;position:absolute;top:50%;left:50%;text-align:center;vertical-align:middle;color:rgb(255,255,255);opacity:0.9;margin:0 0 0 -0.45em;padding:0;line-height:0;font-size:500%;text-shadow:0 0 40px rgba(0,0,0,0.5)">&#9654;</span></div>' . PHP_EOL;

			// watermark
			if ( isset( $this->video->skin ) && isset( $this->video->skin->watermark ) ) {
				$html .= '<div style="position:relative;margin-top:-40px;height:25px;margin-bottom:35px;';
				if ( $this->video->text_direction === 'rtl' ) {
					$html .= 'margin-left:20px;text-align:left;';
				} else {
					$html .= 'margin-right:20px;text-align:right;';
				}
				$html .= 'vertical-align:bottom;z-index:3">';
				$html .= '<img alt="" src="' . esc_url( $this->video->skin->watermark, array( 'http', 'https' ) ) . '" width="90" height="13" style="background-color:transparent;background-image:none;background-repeat:no-repeat;border:none;margin:0;padding:0"/>';
				$html .= '</div>' . PHP_EOL;
			}
		}

		$data = array(
			'blog'     => absint( $this->video->blog_id ),
			'post'     => absint( $this->video->post_id ),
			'duration' => absint( $this->video->duration ),
			'poster'   => esc_url_raw( $this->video->poster_frame_uri, array( 'http', 'https' ) ),
			'hd'       => (bool) $this->options['hd'],
		);
		if ( isset( $this->video->videos ) ) {
			if ( isset( $this->video->videos->mp4 ) && isset( $this->video->videos->mp4->url ) ) {
				$data['mp4'] = array(
					'size' => $this->video->videos->mp4->format,
					'uri'  => esc_url_raw( $this->video->videos->mp4->url, array( 'http', 'https' ) ),
				);
			}
			if ( isset( $this->video->videos->ogv ) && isset( $this->video->videos->ogv->url ) ) {
				$data['ogv'] = array(
					'size' => 'std',
					'uri'  => esc_url_raw( $this->video->videos->ogv->url, array( 'http', 'https' ) ),
				);
			}
		}
		$locale = array( 'dir' => $this->video->text_direction );
		if ( isset( $this->video->language ) ) {
			$locale['lang'] = $this->video->language;
		}
		$data['locale'] = $locale;
		unset( $locale );

		$guid    = $this->video->guid;
		$guid_js = wp_json_encode( $guid );
		$html   .= '<script type="text/javascript">' . PHP_EOL;
		$html   .= 'jQuery(document).ready(function() {';

		$html .= 'if ( !jQuery.VideoPress.data[' . wp_json_encode( $guid ) . '] ) { jQuery.VideoPress.data[' . wp_json_encode( $guid ) . '] = new Array(); }' . PHP_EOL;
		$html .= 'jQuery.VideoPress.data[' . wp_json_encode( $guid ) . '][' . self::$shown[ $guid ] . ']=' . wp_json_encode( $data ) . ';' . PHP_EOL;
		unset( $data );

		$jq_container   = wp_json_encode( '#' . $this->video_container_id );
		$jq_placeholder = wp_json_encode( '#' . $video_placeholder_id );
		$player_config  = "{width:{$width},height:{$height},";
		if ( isset( $this->options['freedom'] ) && $this->options['freedom'] === true ) {
			$player_config .= 'freedom:"true",';
		}
		$player_config .= 'container:jQuery(' . $jq_container . ')}';

		$html .= "jQuery({$jq_placeholder}).show(0,function(){jQuery.VideoPress.analytics.impression({$guid_js})});" . PHP_EOL;

		if ( $age_gate_required ) {
			$html .= 'if ( jQuery.VideoPress.support.flash() ) {' . PHP_EOL;
			/**
			 * Insert alternative content for Flash players.
			 *
			 * @link https://github.com/swfobject/swfobject/wiki/SWFObject-API#swfobjectembedswfswfurlstr-replaceelemidstr-widthstr-heightstr-swfversionstr-xiswfurlstr-flashvarsobj-parobj-attobj-callbackfn
			 */
			$html .= 'swfobject.embedSWF(' . implode(
				',',
				array(
					'jQuery.VideoPress.video.flash.player_uri',
					wp_json_encode( $this->video_container_id ),
					wp_json_encode( $width ),
					wp_json_encode( $height ),
					'jQuery.VideoPress.video.flash.min_version',
					'jQuery.VideoPress.video.flash.expressinstall', // attempt to upgrade the Flash player if less than min_version. requires a 310x137 container or larger but we will always try to include
					'{guid:' . $guid_js . '}', // FlashVars
					'jQuery.VideoPress.video.flash.params',
					'null', // no attributes
					'jQuery.VideoPress.video.flash.embedCallback', // error fallback
				)
			) . ');';
			$html .= '} else {' . PHP_EOL;
			$html .= "if ( jQuery.VideoPress.video.prepare({$guid_js},{$player_config}," . self::$shown[ $guid ] . ') ) {' . PHP_EOL;
			$html .= 'if ( jQuery(' . $jq_container . ').data( "player" ) === "flash" ){jQuery.VideoPress.video.play(jQuery(' . wp_json_encode( '#' . $this->video_container_id ) . '));}else{';
			$html .= 'jQuery(' . $jq_placeholder . ').html(' . wp_json_encode( $this->html_age_date() ) . ');' . PHP_EOL;
			$html .= 'jQuery(' . wp_json_encode( '#' . $video_placeholder_id . ' input[type=submit]' ) . ').one("click", function(event){jQuery.VideoPress.requirements.isSufficientAge(jQuery(' . $jq_container . '),' . absint( $this->video->age_rating ) . ')});' . PHP_EOL;
			$html .= '}}}' . PHP_EOL;
		} else {
			$html .= "if ( jQuery.VideoPress.video.prepare({$guid_js}, {$player_config}," . self::$shown[ $guid ] . ') ) {' . PHP_EOL;
			if ( isset( $this->options['autoplay'] ) && $this->options['autoplay'] === true ) {
				$html .= "jQuery.VideoPress.video.play(jQuery({$jq_container}));";
			} else {
				$html .= 'jQuery(' . $jq_placeholder . ').one("click",function(){jQuery.VideoPress.video.play(jQuery(' . $jq_container . '))});';
			}
			$html .= '}';

			// close the jQuery(document).ready() function
			$html .= '});';
		}
		$html .= '</script>' . PHP_EOL;
		$html .= '</div>' . PHP_EOL;

		/*
		 * JavaScript required
		 */
		$noun = __( 'this video', 'jetpack' );
		if ( ! $age_gate_required ) {
			$vid_type = '';
			if ( ( isset( $this->options['freedom'] ) && $this->options['freedom'] === true ) && ( isset( $this->video->videos->ogv ) && isset( $this->video->videos->ogv->url ) ) ) {
				$vid_type = 'ogv';
			} elseif ( isset( $this->video->videos->mp4 ) && isset( $this->video->videos->mp4->url ) ) {
				$vid_type = 'mp4';
			} elseif ( isset( $this->video->videos->ogv ) && isset( $this->video->videos->ogv->url ) ) {
				$vid_type = 'ogv';
			}

			if ( $vid_type !== '' ) {
				$noun = '<a ';
				if ( isset( $this->video->language ) ) {
					$noun .= 'hreflang="' . esc_attr( $this->video->language ) . '" ';
				}
				if ( $vid_type === 'mp4' ) {
					$noun .= 'type="video/mp4" href="' . esc_url( $this->video->videos->mp4->url, array( 'http', 'https' ) );
				} elseif ( $vid_type === 'ogv' ) {
					$noun .= 'type="video/ogv" href="' . esc_url( $this->video->videos->ogv->url, array( 'http', 'https' ) );
				}
				$noun .= '">';
				if ( isset( $this->video->title ) ) {
					$noun .= esc_html( $this->video->title );
				} else {
					$noun .= __( 'this video', 'jetpack' );
				}
				$noun .= '</a>';
			} elseif ( ! empty( $this->title ) ) {
				$noun = esc_html( $this->title );
			}
			unset( $vid_type );
		}
		/* translators: %s video title or generic 'this video' string */
		$html .= '<noscript><p>' . sprintf( _x( 'JavaScript required to play %s.', 'Play as in playback or view a movie', 'jetpack' ), $noun ) . '</p></noscript>';

		return $html;
	}

	/**
	 * Output for the non-legacy HTML5 player.
	 */
	public function html5_dynamic_next() {
		$video_container_id = 'v-' . $this->video->guid;

		Jwt_Token_Bridge::enqueue_jwt_token_bridge();

		// Must not use iframes for IE11 due to a fullscreen bug
		if ( isset( $_SERVER['HTTP_USER_AGENT'] ) && stristr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 'Trident/7.0; rv:11.0' ) ) {
			$iframe_embed = false;
		} else {

			/**
			 * Filter the VideoPress iframe embed
			 *
			 * This filter allows you to control whether the videos will be embedded using an iframe.
			 * Set this to false in order to use an in-page embed rather than an iframe.
			 *
			 * @module videopress
			 *
			 * @since 3.7.0
			 *
			 * @param boolean $videopress_player_use_iframe
			 */
			$iframe_embed = apply_filters( 'jetpack_videopress_player_use_iframe', true );
		}

		if ( ! array_key_exists( 'hd', $this->options ) ) {
			$this->options['hd'] = (bool) get_option( 'video_player_high_quality', false );
		}

		if ( ! array_key_exists( 'cover', $this->options ) ) {
			$this->options['cover'] = true;
		}

		$videopress_options = array(
			'width'  => absint( $this->video->calculated_width ),
			'height' => absint( $this->video->calculated_height ),
		);
		foreach ( $this->options as $option => $value ) {
			switch ( $option ) {
				case 'at':
					if ( (int) $value ) {
						$videopress_options[ $option ] = (int) $value;
					}
					break;
				case 'autoplay':
					$option = 'autoPlay'; // Fall-through ok.
				case 'hd':
				case 'loop':
				case 'permalink':
				case 'cover':
				case 'muted':
				case 'controls':
				case 'playsinline':
				case 'useAverageColor':
					if ( in_array( $value, array( true, 1, 'true' ), true ) ) {
						$videopress_options[ $option ] = true;
					} elseif ( in_array( $value, array( false, 0, 'false' ), true ) ) {
						$videopress_options[ $option ] = false;
					}
					// phpcs:enable
					break;
				case 'defaultlangcode':
					$option = 'defaultLangCode';
					if ( $value ) {
						$videopress_options[ $option ] = $value;
					}
					break;
				case 'preloadContent':
					if ( $value ) {
						$videopress_options['preloadContent'] = $value;
					}
			}
		}

		if ( $iframe_embed ) {
			$iframe_url = "https://videopress.com/embed/{$this->video->guid}";

			foreach ( $videopress_options as $option => $value ) {
				if ( ! in_array( $option, array( 'width', 'height' ), true ) ) {

					// add_query_arg ignores false as a value, so replacing it with 0
					$iframe_url = add_query_arg( $option, ( false === $value ) ? 0 : $value, $iframe_url );
				}
			}

			$cover  = $videopress_options['cover'] ? ' data-resize-to-parent="true"' : '';
			$js_url = 'https://s0.wp.com/wp-content/plugins/video/assets/js/next/videopress-iframe.js';
			// phpcs:disable WordPress.WP.EnqueuedResources.NonEnqueuedScript
			return "<iframe title='" . __( 'VideoPress Video Player', 'jetpack' )
				. "' aria-label='" . __( 'VideoPress Video Player', 'jetpack' )
				. "' width='" . esc_attr( $videopress_options['width'] )
				. "' height='" . esc_attr( $videopress_options['height'] )
				. "' src='" . esc_attr( $iframe_url )
				. "' frameborder='0' allowfullscreen"
				. $cover
				. " allow='clipboard-write'></iframe>"
				. "<script src='" . esc_attr( $js_url ) . "'></script>";

		} else {
			$videopress_options = wp_json_encode( $videopress_options );
			$js_url             = 'https://s0.wp.com/wp-content/plugins/video/assets/js/videojs/videopress.js';

			return "<div id='{$video_container_id}'></div>
				<script src='{$js_url}'></script>
				<script>
					videopress('{$this->video->guid}', document.querySelector('#{$video_container_id}'), {$videopress_options});
				</script>";
			// phpcs:enable WordPress.WP.EnqueuedResources.NonEnqueuedScript
		}
	}

	/**
	 * Only allow legitimate Flash parameters and their values
	 *
	 * @since 1.2
	 * @link https://helpx.adobe.com/flash/kb/flash-object-embed-tag-attributes.html Flash object and embed attributes
	 * @link https://helpx.adobe.com/flash/kb/font-outlines-device-fonts.html devicefont
	 * @link https://helpx.adobe.com/flash/kb/control-access-scripts-host-web.html allowscriptaccess
	 * @link https://www.adobe.com/devnet/flashplayer/articles/full_screen_mode.html full screen mode
	 * @link https://help.adobe.com/en_US/as3/dev/WS1EFE2EDA-026D-4d14-864E-79DFD56F87C6.html allownetworking
	 * @param array $flash_params Flash parameters expressed in key-value form.
	 * @return array validated Flash parameters
	 */
	public static function esc_flash_params( $flash_params ) {
		$allowed_params = array(
			'swliveconnect'         => array( 'true', 'false' ),
			'play'                  => array( 'true', 'false' ),
			'loop'                  => array( 'true', 'false' ),
			'menu'                  => array( 'true', 'false' ),
			'quality'               => array( 'low', 'autolow', 'autohigh', 'medium', 'high', 'best' ),
			'scale'                 => array( 'default', 'noborder', 'exactfit', 'noscale' ),
			'align'                 => array( 'l', 'r', 't' ),
			'salign'                => array( 'l', 'r', 't', 'tl', 'tr', 'bl', 'br' ),
			'wmode'                 => array( 'window', 'opaque', 'transparent', 'direct', 'gpu' ),
			'devicefont'            => array( '_sans', '_serif', '_typewriter' ),
			'allowscriptaccess'     => array( 'always', 'samedomain', 'never' ),
			'allownetworking'       => array( 'all', 'internal', 'none' ),
			'seamlesstabbing'       => array( 'true', 'false' ),
			'allowfullscreen'       => array( 'true', 'false' ),
			'fullScreenAspectRatio' => array( 'portrait', 'landscape' ),
			'base',
			'bgcolor',
			'flashvars',
		);

		$allowed_params_keys = array_keys( $allowed_params );

		$filtered_params = array();
		foreach ( $flash_params as $param => $value ) {
			if ( empty( $param ) || empty( $value ) ) {
				continue;
			}
			$param = strtolower( $param );
			if ( in_array( $param, $allowed_params_keys, true ) ) {
				if ( isset( $allowed_params[ $param ] ) && is_array( $allowed_params[ $param ] ) ) {
					$value = strtolower( $value );
					if ( in_array( $value, $allowed_params[ $param ], true ) ) {
						$filtered_params[ $param ] = $value;
					}
				} else {
					$filtered_params[ $param ] = $value;
				}
			}
		}
		unset( $allowed_params_keys );

		/**
		 * Flash specifies sameDomain, not samedomain. change from lowercase value for preciseness
		 */
		if ( isset( $filtered_params['allowscriptaccess'] ) && $filtered_params['allowscriptaccess'] === 'samedomain' ) {
			$filtered_params['allowscriptaccess'] = 'sameDomain';
		}

		return $filtered_params;
	}

	/**
	 * Filter Flash variables from the response, taking into consideration player options.
	 *
	 * @since 1.3
	 * @return array Flash variable key value pairs
	 */
	private function get_flash_variables() {
		if ( ! isset( $this->video->players->swf->vars ) ) {
			return array();
		}

		$flashvars = (array) $this->video->players->swf->vars;
		if ( isset( $this->options['autoplay'] ) && $this->options['autoplay'] === true ) {
			$flashvars['autoPlay'] = 'true';
		}
		return $flashvars;
	}

	/**
	 * Validate and filter Flash parameters
	 *
	 * @since 1.3
	 * @return array Flash parameters passed through key and value validation
	 */
	private function get_flash_parameters() {
		if ( ! isset( $this->video->players->swf->params ) ) {
			return array();
		} else {
			return self::esc_flash_params(
				/**
						 * Filters the Flash parameters of the VideoPress player.
						 *
						 * @module videopress
						 *
						 * @since 1.2.0
						 *
						 * @param array $this->video->players->swf->params Array of swf parameters for the VideoPress flash player.
						 */
				apply_filters( 'video_flash_params', (array) $this->video->players->swf->params, 10, 1 )
			);
		}
	}

	/**
	 * Flash player markup in a HTML embed element.
	 *
	 * @since 1.1
	 * @link https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-embed-element embed element
	 * @link http://www.google.com/support/reader/bin/answer.py?answer=70664 Google Reader markup support
	 * @return string HTML markup. Embed element with no children
	 */
	private function flash_embed() {
		wp_enqueue_script( 'videopress' );
		if ( ! isset( $this->video->players->swf ) || ! isset( $this->video->players->swf->url ) ) {
			return '';
		}

		$embed = array(
			'id'     => $this->video_id,
			'src'    => esc_url_raw( $this->video->players->swf->url . '&' . http_build_query( $this->get_flash_variables(), null, '&' ), array( 'http', 'https' ) ),
			'type'   => 'application/x-shockwave-flash',
			'width'  => $this->video->calculated_width,
			'height' => $this->video->calculated_height,
		);
		if ( isset( $this->video->title ) ) {
			$embed['title'] = $this->video->title;
		}
		$embed = array_merge( $embed, $this->get_flash_parameters() );

		$html = '<embed';
		foreach ( $embed as $attribute => $value ) {
			$html .= ' ' . esc_html( $attribute ) . '="' . esc_attr( $value ) . '"';
		}
		unset( $embed );
		$html .= '></embed>';
		return $html;
	}

	/**
	 * Double-baked Flash object markup for Internet Explorer and more standards-friendly consuming agents.
	 *
	 * @since 1.1
	 * @return HTML markup. Object and children.
	 */
	private function flash_object() {
		wp_enqueue_script( 'videopress' );
		if ( ! isset( $this->video->players->swf ) || ! isset( $this->video->players->swf->url ) ) {
			return '';
		}

		$thumbnail_html = '<img alt="';
		if ( isset( $this->video->title ) ) {
			$thumbnail_html .= esc_attr( $this->video->title );
		}
		$thumbnail_html .= '" src="' . esc_url( $this->video->poster_frame_uri, array( 'http', 'https' ) ) . '" width="' . $this->video->calculated_width . '" height="' . $this->video->calculated_height . '" />';
		$flash_vars      = esc_attr( http_build_query( $this->get_flash_variables(), null, '&' ) );
		$flash_params    = '';
		foreach ( $this->get_flash_parameters() as $attribute => $value ) {
			$flash_params .= '<param name="' . esc_attr( $attribute ) . '" value="' . esc_attr( $value ) . '" />';
		}
		/* translators: %s url to the Adobe Flash Player website */
		$flash_help       = sprintf( __( 'This video requires <a rel="nofollow noopener noreferrer" href="%s" target="_blank">Adobe Flash</a> for playback.', 'jetpack' ), 'https://get.adobe.com/flashplayer/' );
		$flash_player_url = esc_url( $this->video->players->swf->url, array( 'http', 'https' ) );
		$description      = '';
		if ( isset( $this->video->title ) ) {
			$standby     = $this->video->title;
			$description = '<p><strong>' . esc_html( $this->video->title ) . '</strong></p>';
		} else {
			$standby = __( 'Loading video...', 'jetpack' );
		}
		$standby = ' standby="' . esc_attr( $standby ) . '"';
		return <<<OBJECT
<script type="text/javascript">if(typeof swfobject!=="undefined"){swfobject.registerObject("{$this->video_id}", "{$this->video->players->swf->version}");}</script>
<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" width="{$this->video->calculated_width}" height="{$this->video->calculated_height}" id="{$this->video_id}"{$standby}>
	<param name="movie" value="{$flash_player_url}" />
	{$flash_params}
	<param name="flashvars" value="{$flash_vars}" />
	<!--[if !IE]>-->
	<object type="application/x-shockwave-flash" data="{$flash_player_url}" width="{$this->video->calculated_width}" height="{$this->video->calculated_height}"{$standby}>
		{$flash_params}
		<param name="flashvars" value="{$flash_vars}" />
	<!--<![endif]-->
	{$thumbnail_html}{$description}<p class="robots-nocontent">{$flash_help}</p>
	<!--[if !IE]>-->
	</object>
	<!--<![endif]-->
</object>
OBJECT;
	}
}
