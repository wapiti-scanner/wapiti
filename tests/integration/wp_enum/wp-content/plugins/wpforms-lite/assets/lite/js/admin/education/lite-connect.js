/* global wpforms_education_lite_connect, WPFormsChallenge */
/**
 * WPForms Education for Lite.
 *
 * Lite Connect feature.
 *
 * @since 1.7.4
 */

'use strict';

var WPFormsEducation = window.WPFormsEducation || {};

WPFormsEducation.liteConnect = window.WPFormsEducation.liteConnect || ( function( document, window, $ ) {

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.4
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.7.4
		 */
		init: function() {

			$( app.ready );

			// Page load.
			$( window ).on( 'load', function() {

				// In the case of jQuery 3.+, we need to wait for a ready event first.
				if ( typeof $.ready.then === 'function' ) {
					$.ready.then( app.load );
				} else {
					app.load();
				}
			} );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.7.4
		 */
		ready: function() {

		},

		/**
		 * Page load.
		 *
		 * @since 1.7.4
		 */
		load: function() {

			app.events();
			app.initLiteConnectToggle();
			app.maybeRevealBuilderTopBar();
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.7.4
		 */
		events: function() {

			app.enableLiteConnectToggleClick();
			app.enableLiteConnectButtonClick();
			app.dismissBuilderTopBarClick();
			app.autoSaveToggleChange();
		},

		/**
		 * Init Lite Connect toggle.
		 *
		 * @since 1.7.5
		 */
		initLiteConnectToggle: function() {
			$( '.wpforms-toggle-control.wpforms-setting-lite-connect-auto-save-toggle input' ).prop( 'disabled', false );
		},

		/**
		 * Enable Lite Connect toggle mousedown handler.
		 *
		 * @since 1.7.4
		 */
		enableLiteConnectToggleClick: function() {

			$( document ).on(
				'mousedown touchstart',
				'.wpforms-toggle-control.wpforms-setting-lite-connect-auto-save-toggle',
				function( event ) {

					var $input = $( this ).find( 'input' ),
						isEnabled = $input.is( ':checked' ),
						isTouchDevice = 'ontouchstart' in document.documentElement;

					if ( ! isTouchDevice ) {
						event.preventDefault();
					}

					if ( $input.prop( 'disabled' ) ) {
						return;
					}

					app.openSettingsLiteConnectModal( isEnabled, function() {

						$input
							.trigger( 'click' )
							.prop( 'disabled', true );
					} );
				}
			);
		},

		/**
		 * Enable Lite Connect button click handler.
		 *
		 * @since 1.7.4
		 */
		enableLiteConnectButtonClick: function() {

			$( document ).on(
				'click',
				'.wpforms-dyk-lite-connect .button-primary',
				function( event ) {

					event.preventDefault();

					var $button = $( this );

					if ( $button.hasClass( 'wpforms-is-enabled' ) ) {
						window.open( $button.attr( 'href' ) );

						return;
					}

					app.openSettingsLiteConnectModal(
						false,
						app.enableLiteConnectButtonModalConfirm
					);
				}
			);
		},

		/**
		 * Enable Lite Connect button modal confirm Callback.
		 *
		 * @since 1.7.4
		 */
		enableLiteConnectButtonModalConfirm: function() {

			var $toggle = $( '.wpforms-dyk-lite-connect .button-primary' );

			app.saveSettingAjaxPost( true, $toggle, function() {

				app.switchSettingView( true, $toggle );
			} );
		},

		/**
		 * Form Entry Backups information modal.
		 *
		 * @since 1.7.4
		 *
		 * @param {boolean}  isEnabled       Current setting state.
		 * @param {Function} confirmCallback Confirm button action.
		 */
		openSettingsLiteConnectModal: function( isEnabled, confirmCallback ) {

			if ( isEnabled ) {
				app.openSettingsLiteConnectDisableModal( confirmCallback );
			} else {
				app.openSettingsLiteConnectEnableModal( confirmCallback );
			}
		},

		/**
		 * Form Entry Backups enable information modal.
		 *
		 * @since 1.7.4
		 *
		 * @param {Function} confirmCallback Confirm button action.
		 */
		openSettingsLiteConnectEnableModal: function( confirmCallback ) {

			$.alert( {
				title: false,
				content: wp.template( 'wpforms-settings-lite-connect-modal-content' )(),
				icon: false,
				type: 'orange',
				boxWidth: '550px',
				theme: 'modern',
				useBootstrap: false,
				scrollToPreviousElement: false,
				buttons: {
					confirm: {
						text: wpforms_education_lite_connect.enable_modal.confirm,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							if ( typeof confirmCallback === 'function' ) {
								confirmCallback();
							}

							// Maybe close Challenge popup.
							if ( window.WPFormsChallenge ) {
								var completeChallenge = WPFormsChallenge.embed && WPFormsChallenge.embed.completeChallenge;
							}

							if ( typeof completeChallenge === 'function' ) {
								completeChallenge();
							}
						},
					},
					cancel: {
						text: wpforms_education_lite_connect.enable_modal.cancel,
						action: function() {

							$( '.wpforms-challenge-popup-container' ).removeClass( 'wpforms-invisible' );
						},
					},
				},
				onOpenBefore: function() {

					$( 'body' ).addClass( 'wpforms-setting-lite-connect-modal' );
					$( '.wpforms-challenge-popup-container' ).addClass( 'wpforms-invisible' );
				},
				onDestroy: function() {

					$( 'body' ).removeClass( 'wpforms-setting-lite-connect-modal' );
				},
			} );
		},

		/**
		 * Form Entry Backups disable information modal.
		 *
		 * @since 1.7.4
		 *
		 * @param {Function} confirmCallback Confirm button action.
		 */
		openSettingsLiteConnectDisableModal: function( confirmCallback ) {

			$.alert( {
				title: wpforms_education_lite_connect.disable_modal.title,
				content: wpforms_education_lite_connect.disable_modal.content,
				icon: 'fa fa-exclamation-circle',
				type: 'red',
				boxWidth: '400px',
				theme: 'modern',
				useBootstrap: false,
				animateFromElement: false,
				scrollToPreviousElement: false,
				buttons: {
					cancel: {
						text: wpforms_education_lite_connect.disable_modal.cancel,
						keys: [ 'enter' ],
						btnClass: 'btn-confirm',
					},
					confirm: {
						text: wpforms_education_lite_connect.disable_modal.confirm,
						action: function() {

							if ( typeof confirmCallback === 'function' ) {
								confirmCallback();
							}
						},
					},
				},
			} );
		},

		/**
		 * Save Lite Connect Enabled setting AJAX post call.
		 *
		 * @since 1.7.4
		 *
		 * @param {boolean}          isEnabled       Lite Connect setting flag.
		 * @param {jQuery|undefined} $toggle         Toggle control outer element.
		 * @param {Function}         successCallback Success result callback.
		 */
		saveSettingAjaxPost: function( isEnabled, $toggle, successCallback ) {

			$toggle = $toggle || $();

			var $input = $toggle.find( 'input' );

			// Perform AJAX request.
			$.post(
				wpforms_education_lite_connect.ajax_url,
				{
					action: 'wpforms_update_lite_connect_enabled_setting',
					value: isEnabled ? 1 : 0,
					nonce: wpforms_education_lite_connect.nonce,
				}
			).done( function( res ) {

				if ( ! res.success ) {
					$input.prop( 'checked', ! isEnabled );
					app.updateResultModal( 'error' );

					return;
				}

				app.updateResultModal( isEnabled ? 'enabled' : 'disabled' );

				if ( typeof successCallback === 'function' ) {
					successCallback();
				}

			} ).fail( function( xhr, textStatus, e ) {

				$input.prop( 'checked', ! isEnabled );
				app.updateResultModal( 'error' );

			} ).always( function( xhr, textStatus, e ) {
				$input.prop( 'disabled', false );
			} );
		},

		/**
		 * Lite Connect toggle `change` event handler with "auto save" feature.
		 *
		 * @since 1.7.4
		 */
		autoSaveToggleChange: function() {

			$( document ).on(
				'change',
				'.wpforms-toggle-control.wpforms-setting-lite-connect-auto-save-toggle input',
				function() {

					var $input    = $( this ),
						$toggle   = $input.closest( '.wpforms-toggle-control' ),
						isEnabled = $input.is( ':checked' );

					app.saveSettingAjaxPost( isEnabled, $toggle, function() {
						app.switchSettingView( isEnabled, $toggle );
					} );
				}
			);
		},

		/**
		 * After updating setting via AJAX we should hide toggle container and show info container.
		 *
		 * @since 1.7.4
		 *
		 * @param {boolean} isEnabled Toggle state.
		 * @param {jQuery}  $toggle   Toggle control.
		 */
		switchSettingView: function( isEnabled, $toggle ) {

			var $wrapper     = $toggle.closest( '.wpforms-education-lite-connect-wrapper' ),
				$setting     = $wrapper.find( '.wpforms-education-lite-connect-setting' ),
				$enabledInfo = $wrapper.find( '.wpforms-education-lite-connect-enabled-info' );

			$setting.toggleClass( 'wpforms-hidden', isEnabled );
			$enabledInfo.toggleClass( 'wpforms-hidden', ! isEnabled );
		},

		/**
		 * Update result message modal.
		 *
		 * @since 1.7.4
		 *
		 * @param {string} msg Message slug.
		 */
		updateResultModal: function( msg ) {

			if ( ! wpforms_education_lite_connect.update_result[ msg ] ) {
				return;
			}

			$.alert( {
				title: wpforms_education_lite_connect.update_result[ msg + '_title' ],
				content: wpforms_education_lite_connect.update_result[ msg ],
				icon: 'fa fa-check-circle',
				type: msg === 'error' ? 'red' : 'green',
				theme: 'modern',
				boxWidth: '400px',
				useBootstrap: false,
				animation: 'scale',
				closeAnimation: 'scale',
				animateFromElement: false,
				scrollToPreviousElement: false,
				buttons: {
					confirm: {
						text    : wpforms_education_lite_connect.update_result.close,
						btnClass: 'btn-confirm',
						keys    : [ 'enter' ],
					},
				},
			} );
		},

		/**
		 * Reveal top bar in the Form Builder.
		 *
		 * @since 1.7.4
		 */
		maybeRevealBuilderTopBar: function() {

			// Skip it is not Form Builder or Entry Backups is already enabled or top bar is dismissed.
			if (
				! window.wpforms_builder ||
				wpforms_education_lite_connect.is_enabled === '1' ||
				$( '#wpforms-builder-lite-connect-top-bar' ).length === 0
			) {
				return;
			}

			setTimeout( function() {
				app.toggleBuilderTopBar( true );
			}, 3000 );
		},

		/**
		 * Toggle top bar in the Form Builder.
		 *
		 * @since 1.7.4
		 *
		 * @param {boolean} open True for open, false for close.
		 */
		toggleBuilderTopBar: function( open ) {

			var cssVar = '--wpforms-admin-bar-height',
				root = document.documentElement,
				adminBarHeight = parseInt( getComputedStyle( root ).getPropertyValue( cssVar ), 10 ),
				topBarHeight = 45;

			adminBarHeight += open ? topBarHeight : -topBarHeight;

			root.setAttribute(
				'style',
				cssVar + ': ' + ( adminBarHeight ) + 'px!important;'
			);
		},

		/**
		 * Dismiss top bar in the Form Builder.
		 *
		 * @since 1.7.4
		 */
		dismissBuilderTopBarClick: function() {

			$( document ).on(
				'click',
				'#wpforms-builder-lite-connect-top-bar .wpforms-dismiss-button',
				function() {
					app.toggleBuilderTopBar( false );
				}
			);
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsEducation.liteConnect.init();
