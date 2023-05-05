/* global wpforms_admin_form_embed_wizard, WPFormsBuilder, ajaxurl, WPFormsChallenge, wpforms_builder, WPForms */

/**
 * Form Embed Wizard function.
 *
 * @since 1.6.2
 */

'use strict';

var WPFormsFormEmbedWizard = window.WPFormsFormEmbedWizard || ( function( document, window, $ ) {

	/**
	 * Elements.
	 *
	 * @since 1.6.2
	 *
	 * @type {object}
	 */
	var el = {};

	/**
	 * Runtime variables.
	 *
	 * @since 1.6.2
	 * @since 1.7.9 Added `lastEmbedSearchPageTerm` property.
	 *
	 * @type {object}
	 */
	var vars = {
		formId:                  0,
		isBuilder:               false,
		isChallengeActive:       false,
		lastEmbedSearchPageTerm: '',
	};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.6.2
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.6.2
		 */
		init: function() {

			$( app.ready );
			$( window ).on( 'load', function() {

				// in case of jQuery 3.+ we need to wait for an `ready` event first.
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
		 * @since 1.6.2
		 */
		ready: function() {

			app.initVars();
			app.events();
		},

		/**
		 * Window load.
		 *
		 * @since 1.6.2
		 * @since 1.7.9 Initialize 'Select Pages' ChoicesJS.
		 */
		load: function() {

			// Initialize tooltip in page editor.
			if ( wpforms_admin_form_embed_wizard.is_edit_page === '1' && ! vars.isChallengeActive ) {
				app.initTooltip();
			}

			// Initialize wizard state in the form builder only.
			if ( vars.isBuilder ) {
				app.initialStateToggle();
			}

			app.initSelectPagesChoicesJS();
		},

		/**
		 * Init variables.
		 *
		 * @since 1.6.2
		 */
		initVars: function() {

			// Caching some DOM elements for further use.
			el = {
				$wizardContainer:   $( '#wpforms-admin-form-embed-wizard-container' ),
				$wizard:            $( '#wpforms-admin-form-embed-wizard' ),
				$contentInitial:    $( '#wpforms-admin-form-embed-wizard-content-initial' ),
				$contentSelectPage: $( '#wpforms-admin-form-embed-wizard-content-select-page' ),
				$contentCreatePage: $( '#wpforms-admin-form-embed-wizard-content-create-page' ),
				$sectionBtns:       $( '#wpforms-admin-form-embed-wizard-section-btns' ),
				$sectionGo:         $( '#wpforms-admin-form-embed-wizard-section-go' ),
				$newPageTitle:      $( '#wpforms-admin-form-embed-wizard-new-page-title' ),
				$selectPage:        $( '#wpforms-setting-form-embed-wizard-choicesjs-select-pages' ),
				$videoTutorial:     $( '#wpforms-admin-form-embed-wizard-tutorial' ),
				$sectionToggles:    $( '#wpforms-admin-form-embed-wizard-section-toggles' ),
				$sectionGoBack:     $( '#wpforms-admin-form-embed-wizard-section-goback' ),
				$shortcode:         $( '#wpforms-admin-form-embed-wizard-shortcode-wrap' ),
				$shortcodeInput:    $( '#wpforms-admin-form-embed-wizard-shortcode' ),
				$shortcodeCopy:     $( '#wpforms-admin-form-embed-wizard-shortcode-copy' ),
			};

			el.$selectPageContainer = el.$selectPage.parents( 'span.choicesjs-select-wrap' );

			// Detect the form builder screen and store the flag.
			vars.isBuilder = typeof WPFormsBuilder !== 'undefined';

			// Detect the Challenge and store the flag.
			vars.isChallengeActive = typeof WPFormsChallenge !== 'undefined';

			// Are the pages exists?
			vars.pagesExists = el.$wizard.data( 'pages-exists' ) === 1;
		},

		/**
		 * Init ChoicesJS for "Select Pages" field in embed.
		 *
		 * @since 1.7.9
		 */
		initSelectPagesChoicesJS: function() {

			if ( el.$selectPage.length <= 0 ) {
				return;
			}

			const useAjax = el.$selectPage.data( 'use_ajax' ) === 1;

			WPForms.Admin.Builder.WPFormsChoicesJS.setup(
				el.$selectPage[0],
				{},
				{
					action: 'wpforms_admin_form_embed_wizard_search_pages_choicesjs',
					nonce: useAjax ? wpforms_admin_form_embed_wizard.nonce : null,
				}
			);
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.6.2
		 */
		events: function() {

			// Skip wizard events in the page editor.
			if ( ! el.$wizard.length ) {
				return;
			}

			el.$wizard
				.on( 'click', 'button', app.popupButtonsClick )
				.on( 'click', '.tutorial-toggle', app.tutorialToggle )
				.on( 'click', '.shortcode-toggle', app.shortcodeToggle )
				.on( 'click', '.initialstate-toggle', app.initialStateToggle )
				.on( 'click', '.wpforms-admin-popup-close', app.closePopup )
				.on( 'click', '#wpforms-admin-form-embed-wizard-shortcode-copy', app.copyShortcodeToClipboard );
		},

		/**
		 * Popup buttons events handler.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} e Event object.
		 */
		popupButtonsClick: function( e ) {

			var $btn = $( e.target );

			if ( ! $btn.length ) {
				return;
			}

			var	$div = $btn.closest( 'div' ),
				action = $btn.data( 'action' ) || '';

			el.$contentInitial.hide();

			switch ( action ) {

				// Select existing page.
				case 'select-page':
					el.$newPageTitle.hide();
					el.$contentSelectPage.show();
					break;

				// Create a new page.
				case 'create-page':
					el.$selectPageContainer.hide();
					el.$contentCreatePage.show();
					break;

				// Let's Go!
				case 'go':
					if ( el.$selectPageContainer.is( ':visible' ) && el.$selectPage.val() === '' ) {
						return;
					}
					$btn.prop( 'disabled', true );
					app.saveFormAndRedirect();

					return;
			}

			$div.hide();
			$div.next().fadeIn();
			el.$sectionToggles.hide();
			el.$sectionGoBack.fadeIn();

			// Set focus to the field that is currently displayed.
			$.each( [ el.$selectPage, el.$newPageTitle ], function() {
				if ( this.is( ':visible' ) ) {
					this.trigger( 'focus' );
				}
			} );

			app.tutorialControl( 'Stop' );
		},

		/**
		 * Toggle video tutorial inside popup.
		 *
		 * @since 1.6.2
		 *
		 * @param {object} e Event object.
		 */
		tutorialToggle: function( e ) {

			e.preventDefault();

			el.$shortcode.hide();
			el.$videoTutorial.toggle();

			if ( el.$videoTutorial.attr( 'src' ) === 'about:blank' ) {
				el.$videoTutorial.attr( 'src', wpforms_admin_form_embed_wizard.video_url );
			}

			if ( el.$videoTutorial[0].src.indexOf( '&autoplay=1' ) < 0 ) {
				app.tutorialControl( 'Play' );
			} else {
				app.tutorialControl( 'Stop' );
			}
		},

		/**
		 * Toggle video tutorial inside popup.
		 *
		 * @since 1.6.2.3
		 *
		 * @param {string} action One of 'Play' or 'Stop'.
		 */
		tutorialControl: function( action ) {

			var iframe = el.$videoTutorial[0];

			if ( typeof iframe === 'undefined' ) {
				return;
			}

			if ( action !== 'Stop' ) {
				iframe.src +=  iframe.src.indexOf( '&autoplay=1' ) < 0 ? '&autoplay=1' : '';
			} else {
				iframe.src = iframe.src.replace( '&autoplay=1', '' );
			}
		},

		/**
		 * Toggle shortcode input field.
		 *
		 * @since 1.6.2.3
		 *
		 * @param {object} e Event object.
		 */
		shortcodeToggle: function( e ) {

			e.preventDefault();

			el.$videoTutorial.hide();
			app.tutorialControl( 'Stop' );
			el.$shortcodeInput.val( '[wpforms id="' + vars.formId + '" title="false"]' );
			el.$shortcode.toggle();
		},

		/**
		 * Copies the shortcode embed code to the clipboard.
		 *
		 * @since 1.6.4
		 */
		copyShortcodeToClipboard: function() {

			// Remove disabled attribute, select the text, and re-add disabled attribute.
			el.$shortcodeInput
				.prop( 'disabled', false )
				.select()
				.prop( 'disabled', true );

			// Copy it.
			document.execCommand( 'copy' );

			var $icon = el.$shortcodeCopy.find( 'i' );

			// Add visual feedback to copy command.
			$icon.removeClass( 'fa-files-o' ).addClass( 'fa-check' );

			// Reset visual confirmation back to default state after 2.5 sec.
			window.setTimeout( function() {
				$icon.removeClass( 'fa-check' ).addClass( 'fa-files-o' );
			}, 2500 );
		},

		/**
		 * Toggle initial state.
		 *
		 * @since 1.6.2.3
		 *
		 * @param {object} e Event object.
		 */
		initialStateToggle: function( e ) {

			if ( e ) {
				e.preventDefault();
			}

			if ( vars.pagesExists ) {
				el.$contentInitial.show();
				el.$contentSelectPage.hide();
				el.$contentCreatePage.hide();
				el.$selectPageContainer.show();
				el.$newPageTitle.show();
				el.$sectionBtns.show();
				el.$sectionGo.hide();
			} else {
				el.$contentInitial.hide();
				el.$contentSelectPage.hide();
				el.$contentCreatePage.show();
				el.$selectPageContainer.hide();
				el.$newPageTitle.show();
				el.$sectionBtns.hide();
				el.$sectionGo.show();
			}
			el.$shortcode.hide();
			el.$videoTutorial.hide();
			app.tutorialControl( 'Stop' );
			el.$sectionToggles.show();
			el.$sectionGoBack.hide();
		},

		/**
		 * Save the form and redirect to form embed page.
		 *
		 * @since 1.6.2
		 */
		saveFormAndRedirect: function() {

			// Just redirect if no need to save the form.
			if ( ! vars.isBuilder || WPFormsBuilder.formIsSaved() ) {
				app.embedPageRedirect();
				return;
			}

			// Embedding in Challenge should save the form silently.
			if ( vars.isBuilder && vars.isChallengeActive ) {
				WPFormsBuilder.formSave().done( app.embedPageRedirect );
				return;
			}

			$.confirm( {
				title: false,
				content: wpforms_builder.exit_confirm,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				closeIcon: true,
				buttons: {
					confirm: {
						text: wpforms_builder.save_embed,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {
							WPFormsBuilder.formSave().done( app.embedPageRedirect );
						},
					},
					cancel: {
						text: wpforms_builder.embed,
						action: function() {
							WPFormsBuilder.setCloseConfirmation( false );
							app.embedPageRedirect();
						},
					},
				},
				onClose: function() {
					el.$sectionGo.find( 'button' ).prop( 'disabled', false );
				},
			} );
		},

		/**
		 * Prepare data for requesting redirect URL.
		 *
		 * @since 1.6.2
		 *
		 * @returns {object} AJAX data object.
		 */
		embedPageRedirectAjaxData: function() {

			var data = {
				action  : 'wpforms_admin_form_embed_wizard_embed_page_url',
				_wpnonce: wpforms_admin_form_embed_wizard.nonce,
				formId: vars.formId,
			};

			if ( el.$selectPageContainer.is( ':visible' ) ) {
				data.pageId = el.$selectPage.val();
			}

			if ( el.$newPageTitle.is( ':visible' ) ) {
				data.pageTitle = el.$newPageTitle.val();
			}

			return data;
		},

		/**
		 * Redirect to form embed page.
		 *
		 * @since 1.6.2
		 */
		embedPageRedirect: function() {

			var data = app.embedPageRedirectAjaxData();

			// Exit if no one page is selected.
			if ( typeof data.pageId !== 'undefined' && data.pageId === '' ) {
				return;
			}

			$.post( ajaxurl, data, function( response ) {
				if ( response.success ) {
					window.location = response.data;
				}
			} );
		},

		/**
		 * Display wizard popup.
		 *
		 * @since 1.6.2
		 *
		 * @param {numeric} openFormId Form ID to embed. Used only if called outside the form builder.
		 */
		openPopup: function( openFormId ) {

			openFormId = openFormId || 0;

			vars.formId = vars.isBuilder ? $( '#wpforms-builder-form' ).data( 'id' ) : openFormId;

			// Regular wizard and wizard in Challenge has differences.
			el.$wizard.toggleClass( 'wpforms-challenge-popup', vars.isChallengeActive );
			el.$wizard.find( '.wpforms-admin-popup-content-regular' ).toggle( ! vars.isChallengeActive );
			el.$wizard.find( '.wpforms-admin-popup-content-challenge' ).toggle( vars.isChallengeActive );

			// Re-init sections.
			if ( el.$selectPage.length === 0 ) {
				el.$sectionBtns.hide();
				el.$sectionGo.show();
			} else {
				el.$sectionBtns.show();
				el.$sectionGo.hide();
			}
			el.$newPageTitle.show();
			el.$selectPageContainer.show();

			el.$wizardContainer.fadeIn();
		},

		/**
		 * Close wizard popup.
		 *
		 * @since 1.6.2
		 */
		closePopup: function() {

			el.$wizardContainer.fadeOut();
			app.initialStateToggle();

			$( document ).trigger( 'wpformsWizardPopupClose' );
		},

		/**
		 * Init embed page tooltip.
		 *
		 * @since 1.6.2
		 */
		initTooltip: function() {

			if ( typeof $.fn.tooltipster === 'undefined' ) {
				return;
			}

			var $dot = $( '<span class="wpforms-admin-form-embed-wizard-dot">&nbsp;</span>' ),
				isGutenberg = app.isGutenberg(),
				anchor = isGutenberg ? '.block-editor .edit-post-header' : '#wp-content-editor-tools .wpforms-insert-form-button';

			var tooltipsterArgs = {
				content          : $( '#wpforms-admin-form-embed-wizard-tooltip-content' ),
				trigger          : 'custom',
				interactive      : true,
				animationDuration: 0,
				delay            : 0,
				theme            : [ 'tooltipster-default', 'wpforms-admin-form-embed-wizard' ],
				side             : isGutenberg ? 'bottom' : 'right',
				distance         : 3,
				functionReady    : function( instance, helper ) {

					instance._$tooltip.on( 'click', 'button', function() {

						instance.close();
						$( '.wpforms-admin-form-embed-wizard-dot' ).remove();
					} );

					instance.reposition();
				},
			};

			if ( ! isGutenberg ) {
				$dot.insertAfter( anchor ).tooltipster( tooltipsterArgs ).tooltipster( 'open' );
			}

			// The Gutenberg header can be loaded after the window load event.
			// We have to wait until the Gutenberg heading is added to the DOM.
			const closeAnchorListener = wp.data.subscribe( function() {

				if ( ! $( anchor ).length ) {
					return;
				}

				// Close the listener to avoid an infinite loop.
				closeAnchorListener();

				$dot.insertAfter( anchor ).tooltipster( tooltipsterArgs ).tooltipster( 'open' );
			} );
		},

		/**
		 * Check if we're in Gutenberg editor.
		 *
		 * @since 1.6.2
		 *
		 * @returns {boolean} Is Gutenberg or not.
		 */
		isGutenberg: function() {

			return typeof wp !== 'undefined' && Object.prototype.hasOwnProperty.call( wp, 'blocks' );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPFormsFormEmbedWizard.init();
