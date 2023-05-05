<?php

namespace WPForms\Frontend;

/**
 * Captcha class.
 *
 * @since 1.8.1
 */
class Captcha {

	/**
	 * Initialize class.
	 *
	 * @since 1.8.1
	 */
	public function init() {

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.8.1
	 */
	private function hooks() {

		// Filters.
		add_filter( 'script_loader_tag',  [ $this, 'set_defer_attribute' ], 10, 3 );

		// Actions.
		add_action( 'wpforms_frontend_output', [ $this, 'recaptcha' ], 20, 5 );
		add_action( 'wp_enqueue_scripts', [ $this, 'recaptcha_noconflict' ], 9999 );
		add_action( 'wp_footer', [ $this, 'recaptcha_noconflict' ], 19 );
		add_action( 'wpforms_wp_footer', [ $this, 'assets_recaptcha' ] );
	}

	/**
	 * CAPTCHA output if configured.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data   Form data and settings.
	 * @param null  $deprecated  Deprecated in v1.3.7, previously was $form object.
	 * @param bool  $title       Whether to display form title.
	 * @param bool  $description Whether to display form description.
	 * @param array $errors      List of all errors filled in WPForms_Process::process().
	 *
	 * @noinspection HtmlUnknownAttribute
	 * @noinspection PhpUnusedParameterInspection
	 */
	public function recaptcha( $form_data, $deprecated, $title, $description, $errors ) {

		// Check that CAPTCHA is configured in the settings.
		$captcha_settings = $this->get_form_captcha_settings( $form_data );

		if ( ! $captcha_settings ) {
			return;
		}

		/**
		 * Filters captcha sitekey.
		 *
		 * @since 1.7.1
		 *
		 * @param array $sitekey    Sitekey.
		 * @param array $form_data  Form data and settings.
		 */
		$data = apply_filters( // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
			'wpforms_frontend_recaptcha',
			[ 'sitekey' => $captcha_settings['site_key'] ],
			$form_data
		);

		if ( $captcha_settings['provider'] === 'recaptcha' && $captcha_settings['recaptcha_type'] === 'invisible' ) {
			$data['size'] = 'invisible';
		}

		if ( $captcha_settings['provider'] === 'turnstile' ) {

			/**
			 * Filter Turnstile action value.
			 *
			 * @since 1.8.1
			 *
			 * @param string $action    Action value. Can only contain up to 32 alphanumeric characters including _ and -.
			 * @param array  $form_data Form data and settings.
			 */
			$data['action'] = apply_filters( // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
				'wpforms_frontend_recaptcha_turnstile_action',
				sprintf(
					'FormID-%d',
					$form_data['id']
				),
				$form_data
			);
		}

		$frontend_obj = wpforms()->get( 'frontend' );

		printf(
			'<div class="wpforms-recaptcha-container wpforms-is-%s" %s>',
			sanitize_html_class( $captcha_settings['provider'] ),
			$frontend_obj->pages ? 'style="display:none;"' : ''
		);

		echo '<div ' . wpforms_html_attributes( '', [ 'g-recaptcha' ], $data ) . '></div>';

		if ( ! ( $captcha_settings['provider'] === 'recaptcha' && $captcha_settings['recaptcha_type'] === 'invisible' ) ) {
			echo sprintf(
				'<input type="text" name="g-recaptcha-hidden" class="wpforms-recaptcha-hidden" style="position:absolute!important;clip:rect(0,0,0,0)!important;height:1px!important;width:1px!important;border:0!important;overflow:hidden!important;padding:0!important;margin:0!important;" data-rule-%1$s="1">',
				esc_attr( $captcha_settings['provider'] )
			);
		}

		if ( ! empty( $errors['recaptcha'] ) ) {
			$frontend_obj->form_error( 'recaptcha', $errors['recaptcha'] );
		}

		echo '</div>';
	}

	/**
	 * Get captcha settings for form output.
	 * Return null if captcha is disabled.
	 *
	 * @since 1.8.1
	 *
	 * @param array $form_data Form data and settings.
	 *
	 * @return array|null
	 * @noinspection NullPointerExceptionInspection
	 */
	private function get_form_captcha_settings( $form_data ) {

		$captcha_settings = wpforms_get_captcha_settings();

		if (
			empty( $captcha_settings['provider'] ) ||
			$captcha_settings['provider'] === 'none' ||
			empty( $captcha_settings['site_key'] ) ||
			empty( $captcha_settings['secret_key'] )
		) {
			return null;
		}

		// Check that the CAPTCHA is configured for the specific form.
		if (
			! isset( $form_data['settings']['recaptcha'] ) ||
			$form_data['settings']['recaptcha'] !== '1'
		) {
			return null;
		}

		$is_recaptcha_v3 = $captcha_settings['provider'] === 'recaptcha' && $captcha_settings['recaptcha_type'] === 'v3';

		if ( wpforms()->get( 'amp' )->output_captcha( $is_recaptcha_v3, $captcha_settings, $form_data ) ) {
			return null;
		}

		if ( $is_recaptcha_v3 ) {
			echo '<input type="hidden" name="wpforms[recaptcha]" value="">';

			return null;
		}

		return $captcha_settings;
	}

	/**
	 * Google reCAPTCHA no-conflict mode.
	 *
	 * When enabled in the WPForms settings, forcefully remove all other
	 * reCAPTCHA enqueues to prevent conflicts. Filter can be used to target
	 * specific pages, etc.
	 *
	 * @since 1.4.5
	 * @since 1.6.4 Added hCaptcha support.
	 */
	public function recaptcha_noconflict() {

		$captcha_settings = wpforms_get_captcha_settings();

		if (
			empty( $captcha_settings['provider'] ) ||
			$captcha_settings['provider'] === 'none' ||
			empty( wpforms_setting( 'recaptcha-noconflict' ) ) ||
			/**
			 * Filters recaptcha no conflict flag.
			 *
			 * @since 1.6.4
			 *
			 * @param bool $recaptcha_no_conflict No conflict flag.
			 */
			! apply_filters( 'wpforms_frontend_recaptcha_noconflict', true ) // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
		) {
			return;
		}

		$scripts = wp_scripts();
		$urls    = [ 'google.com/recaptcha', 'gstatic.com/recaptcha', 'hcaptcha.com/1' ];

		foreach ( $scripts->queue as $handle ) {

			// Skip the WPForms javascript-assets.
			if (
				! isset( $scripts->registered[ $handle ] ) ||
				false !== strpos( $scripts->registered[ $handle ]->handle, 'wpforms' )
			) {
				return;
			}

			foreach ( $urls as $url ) {
				if ( false !== strpos( $scripts->registered[ $handle ]->src, $url ) ) {
					wp_dequeue_script( $handle );
					wp_deregister_script( $handle );
					break;
				}
			}
		}
	}

	/**
	 * Load the assets needed for the CAPTCHA.
	 *
	 * @since 1.6.2
	 * @since 1.6.4 Added hCaptcha support.
	 *
	 * @param array $forms Forms being displayed.
	 */
	public function assets_recaptcha( $forms ) {

		$captcha_settings = $this->get_assets_captcha_settings( $forms );

		if ( ! $captcha_settings ) {
			return;
		}

		$is_recaptcha_v3 = $captcha_settings['provider'] === 'recaptcha' && $captcha_settings['recaptcha_type'] === 'v3';
		$recaptcha_url   = $is_recaptcha_v3 ?
			'https://www.google.com/recaptcha/api.js?render=' . $captcha_settings['site_key'] :
			/**
			 * For backward compatibility reason we have to filter only the v2 reCAPTCHA.
			 *
			 * @since 1.4.0
			 *
			 * @param string $url The reCaptcha v2 URL.
			 */
			apply_filters( 'wpforms_frontend_recaptcha_url', 'https://www.google.com/recaptcha/api.js?onload=wpformsRecaptchaLoad&render=explicit' ); // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName

		$captcha_api_array = [
			'hcaptcha'  => 'https://hcaptcha.com/1/api.js?onload=wpformsRecaptchaLoad&render=explicit',
			'recaptcha' => $recaptcha_url,
			'turnstile' => 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=wpformsRecaptchaLoad&render=explicit',
		];
		/**
		 * Filter the CAPTCHA API URL.
		 *
		 * @since 1.6.4
		 *
		 * @param string $captcha_api The CAPTCHA API URL.
		 */
		$captcha_api = apply_filters( 'wpforms_frontend_captcha_api', $captcha_api_array[ $captcha_settings['provider'] ] );

		wp_enqueue_script(
			'wpforms-recaptcha',
			$captcha_api,
			$is_recaptcha_v3 ? [] : [ 'jquery' ],
			null,
			true
		);

		/**
		 * Filter the string containing the CAPTCHA javascript to be added.
		 *
		 * @since 1.6.4
		 *
		 * @param string $captcha_inline The CAPTCHA javascript.
		 */
		$captcha_inline = apply_filters(
			'wpforms_frontend_captcha_inline_script',
			$this->get_captcha_inline_script( $captcha_settings )
		);

		wp_add_inline_script( 'wpforms-recaptcha', $captcha_inline );
	}

	/**
	 * Get captcha settings for assets output.
	 * Return null if captcha is disabled.
	 *
	 * @since 1.8.1
	 *
	 * @param array $forms Forms being displayed.
	 *
	 * @return array|null
	 * @noinspection NullPointerExceptionInspection
	 */
	private function get_assets_captcha_settings( $forms ) {

		/**
		 * Filters disable captcha switch.
		 *
		 * @since 1.6.2
		 *
		 * @param bool $is_captcha_disabled Whether captcha is disabled.
		 */
		if ( apply_filters( 'wpforms_frontend_recaptcha_disable', false ) ) { // phpcs:ignore WPForms.PHP.ValidateHooks.InvalidHookName
			return null;
		}

		// Load CAPTCHA support if form supports it.
		$captcha_settings = wpforms_get_captcha_settings();

		if (
			empty( $captcha_settings['provider'] ) ||
			$captcha_settings['provider'] === 'none' ||
			empty( $captcha_settings['site_key'] ) ||
			empty( $captcha_settings['secret_key'] )
		) {
			return null;
		}

		// Whether at least 1 form on a page has CAPTCHA enabled.
		$captcha = false;

		foreach ( $forms as $form ) {
			if ( ! empty( $form['settings']['recaptcha'] ) ) {
				$captcha = true;

				break;
			}
		}

		// Return early.
		if ( ! $captcha && ! wpforms()->get( 'frontend' )->assets_global() ) {
			return null;
		}

		return $captcha_settings;
	}

	/**
	 * Retrieve the string containing the CAPTCHA inline javascript.
	 *
	 * @since 1.6.4
	 *
	 * @param array $captcha_settings The CAPTCHA settings.
	 *
	 * @return string
	 * @noinspection JSUnusedLocalSymbols
	 * @noinspection UnnecessaryLocalVariableJS
	 * @noinspection JSUnresolvedVariable
	 * @noinspection JSDeprecatedSymbols
	 * @noinspection JSUnresolvedFunction
	 */
	protected function get_captcha_inline_script( $captcha_settings ) {

		// IE11 polyfills for native `matches()` and `closest()` methods.
		$polyfills = /** @lang JavaScript */
			'if (!Element.prototype.matches) {
				Element.prototype.matches = Element.prototype.msMatchesSelector || Element.prototype.webkitMatchesSelector;
			}
			if (!Element.prototype.closest) {
				Element.prototype.closest = function (s) {
					var el = this;
					do {
						if (Element.prototype.matches.call(el, s)) { return el; }
						el = el.parentElement || el.parentNode;
					} while (el !== null && el.nodeType === 1);
					return null;
				};
			}
		';

		// Native equivalent for jQuery's `trigger()` method.
		$dispatch = /** @lang JavaScript */
			'var wpformsDispatchEvent = function (el, ev, custom) {
				var e = document.createEvent(custom ? "CustomEvent" : "HTMLEvents");
				custom ? e.initCustomEvent(ev, true, true, false) : e.initEvent(ev, true, true);
				el.dispatchEvent(e);
			};
		';

		// Update container class after changing Turnstile type.
		$turnstile_update_class = /** @lang JavaScript */
			'var turnstileUpdateContainer = function (el) {
				let form = el.closest( "form" ),
				iframeHeight = el.getElementsByTagName("iframe")[0].style.height;
				
				parseInt(iframeHeight) === 0 ? 
					form.querySelector(".wpforms-is-turnstile").classList.add( "wpforms-is-turnstile-invisible" ) :
					form.querySelector(".wpforms-is-turnstile").classList.remove( "wpforms-is-turnstile-invisible" );
			};
		';

		// Captcha callback, used by hCaptcha and checkbox reCaptcha v2.
		$callback = /** @lang JavaScript */
			'var wpformsRecaptchaCallback = function (el) {
				var hdn = el.parentNode.querySelector(".wpforms-recaptcha-hidden");
				var err = el.parentNode.querySelector("#g-recaptcha-hidden-error");
				hdn.value = "1";
				wpformsDispatchEvent(hdn, "change", false);
				hdn.classList.remove("wpforms-error");
				err && hdn.parentNode.removeChild(err);
			};
		';

		if ( $captcha_settings['provider'] === 'hcaptcha' ) {
			$data  = $dispatch;
			$data .= $callback;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaLoad = function () {
					Array.prototype.forEach.call(document.querySelectorAll(".g-recaptcha"), function (el) {
						var captchaID = hcaptcha.render(el, {
							callback: function () {
								wpformsRecaptchaCallback(el);
							}
						});
						el.setAttribute("data-recaptcha-id", captchaID);
					});
					wpformsDispatchEvent(document, "wpformsRecaptchaLoaded", true);
				};
			';

			return $data;
		}

		if ( $captcha_settings['provider'] === 'turnstile' ) {

			$data  = $dispatch;
			$data .= $callback;
			$data .= $turnstile_update_class;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaLoad = function () {
					Array.prototype.forEach.call(document.querySelectorAll(".g-recaptcha"), function (el) {
						let form = el.closest( "form" ),
						formId = form.dataset.formid,
						captchaID = turnstile.render(el, {
							theme: "' . $captcha_settings['theme'] . '",
							callback: function () {
								turnstileUpdateContainer(el);
								wpformsRecaptchaCallback(el);
							},
							"timeout-callback": function() {
								turnstileUpdateContainer(el);
							}
						});
						el.setAttribute("data-recaptcha-id", captchaID);
					});
					
					wpformsDispatchEvent( document, "wpformsRecaptchaLoaded", true );
				};
			';

			return $data;
		}

		if ( $captcha_settings['recaptcha_type'] === 'v3' ) {
			$data = $dispatch;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaV3Execute = function ( callback ) {
					grecaptcha.execute( "' . $captcha_settings['site_key'] . '", { action: "wpforms" } ).then( function ( token ) {
						Array.prototype.forEach.call( document.getElementsByName( "wpforms[recaptcha]" ), function ( el ) {
							el.value = token;
						} );
						if ( typeof callback === "function" ) {
							return callback();
						}
					} );
				}
				grecaptcha.ready( function () {
					wpformsDispatchEvent( document, "wpformsRecaptchaLoaded", true );
				} );
			';
		} elseif ( $captcha_settings['recaptcha_type'] === 'invisible' ) {
			$data  = $polyfills;
			$data .= $dispatch;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaLoad = function () {
					Array.prototype.forEach.call(document.querySelectorAll(".g-recaptcha"), function (el) {
						try {
							var recaptchaID = grecaptcha.render(el, {
								callback: function () {
									wpformsRecaptchaCallback(el);
								}
							}, true);
							el.closest("form").querySelector("button[type=submit]").recaptchaID = recaptchaID;
						} catch (error) {}
					});
					wpformsDispatchEvent(document, "wpformsRecaptchaLoaded", true);
				};
				var wpformsRecaptchaCallback = function (el) {
					var $form = el.closest("form");
					if (typeof wpforms.formSubmit === "function") {
						wpforms.formSubmit($form);
					} else {
						$form.querySelector("button[type=submit]").recaptchaID = false;
						$form.submit();
					}
				};
			';
		} else {
			$data  = $dispatch;
			$data .= $callback;

			$data .= /** @lang JavaScript */
				'var wpformsRecaptchaLoad = function () {
					Array.prototype.forEach.call(document.querySelectorAll(".g-recaptcha"), function (el) {
						try {
							var recaptchaID = grecaptcha.render(el, {
								callback: function () {
									wpformsRecaptchaCallback(el);
								}
							});
							el.setAttribute("data-recaptcha-id", recaptchaID);
						} catch (error) {}
					});
					wpformsDispatchEvent(document, "wpformsRecaptchaLoaded", true);
				};
			';
		}

		return $data;
	}

	/**
	 * Cloudflare Turnstile captcha requires defer attribute.
	 *
	 * @since 1.8.1
	 *
	 * @param string $tag    HTML for the script tag.
	 * @param string $handle Handle of script.
	 * @param string $src    Src of script.
	 *
	 * @return string
	 */
	public function set_defer_attribute( $tag, $handle, $src ) {

		$captcha_settings = wpforms_get_captcha_settings();

		if ( $captcha_settings['provider'] !== 'turnstile' ) {
			return $tag;
		}

		if ( $handle !== 'wpforms-recaptcha' ) {
			return $tag;
		}

		return str_replace( ' src', ' defer src', $tag );
	}
}
