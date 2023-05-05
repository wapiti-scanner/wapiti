/* global wpforms_settings */

'use strict';

/**
 * Modern Frontend.
 *
 * @since 1.8.1
 */
var WPForms = window.WPForms || {};

WPForms.FrontendModern = WPForms.FrontendModern || ( function( document, window, $ ) {

	let app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.8.1
		 */
		init: function() {

			// Document ready.
			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.8.1
		 */
		ready: function() {

			app.updateGBBlockAccentColors();
			app.initPageBreakButtons();
			app.events();
		},

		/**
		 * Events.
		 *
		 * @since 1.8.1
		 */
		events: function() {

			$( 'form.wpforms-form' )
				.on( 'wpformsCombinedUploadsSizeError', app.combinedUploadsSizeError )
				.on( 'wpformsCombinedUploadsSizeOk', app.combinedUploadsSizeOk )
				.on( 'wpformsFormSubmitButtonDisable', app.formSubmitButtonDisable )
				.on( 'wpformsFormSubmitButtonRestore', app.formSubmitButtonRestore )
				.on( 'wpformsPageChange', app.pageChange );

			$( 'form.wpforms-form .wpforms-submit' )
				.on( 'keydown click', app.disabledButtonPress );
		},

		/**
		 * Update accent colors of some fields in GB block in Modern Markup mode.
		 *
		 * @since 1.8.1
		 */
		updateGBBlockAccentColors: function() {

			// Loop through all the GB blocks on the page.
			$( '.wpforms-block.wpforms-container-full' ).each( function() {

				const $form = $( this );

				app.updateGBBlockPageIndicatorColor( $form );
				app.updateGBBlockIconChoicesColor( $form );
				app.updateGBBlockRatingColor( $form );
			} );
		},

		/**
		 * Update accent color of Page Indicator.
		 *
		 * @since 1.8.1
		 *
		 * @param {jQuery} $form Form container.
		 */
		updateGBBlockPageIndicatorColor: function( $form ) {

			const $indicator = $form.find( '.wpforms-page-indicator' ),
				$indicatorPage = $indicator.find( '.wpforms-page-indicator-page-progress, .wpforms-page-indicator-page.active .wpforms-page-indicator-page-number' ),
				$indicatorTriangle = $indicatorPage.find( '.wpforms-page-indicator-page-triangle' );

			$indicator.data( 'indicator-color', 'var( --wpforms-button-background-color )' );
			$indicatorPage.css( 'background-color', 'var( --wpforms-button-background-color )' );
			$indicatorTriangle.css( 'border-top-color', 'var( --wpforms-button-background-color )' );
		},

		/**
		 * Update accent color of Page Indicator.
		 *
		 * @since 1.8.1
		 *
		 * @param {Element} form Form container DOM element.
		 */
		updateGBBlockPageIndicatorColorF: function( form ) {

			const indicator = form.querySelector( '.wpforms-page-indicator' );

			if ( ! indicator ) {
				return;
			}

			const indicatorPage = indicator.querySelector( '.wpforms-page-indicator-page-progress, .wpforms-page-indicator-page.active .wpforms-page-indicator-page-number' ),
				indicatorTriangle = indicatorPage.querySelector( '.wpforms-page-indicator-page-triangle' );

			indicator.dataset.indicatorColor = 'var( --wpforms-button-background-color )';
			indicatorPage && indicatorPage.style.setProperty( 'background-color', 'var( --wpforms-button-background-color )' );
			indicatorTriangle && indicatorTriangle.style.setProperty( 'border-top-color', 'var( --wpforms-button-background-color )' );
		},

		/**
		 * Update accent color of Icon Choices.
		 *
		 * @since 1.8.1
		 *
		 * @param {jQuery} $form Form container.
		 */
		updateGBBlockIconChoicesColor: function( $form ) {

			$form
				.find( '.wpforms-icon-choices' )
				.css( '--wpforms-icon-choices-color', 'var( --wpforms-button-background-color )' );
		},

		/**
		 * Update accent color of Rating field.
		 *
		 * @since 1.8.1
		 *
		 * @param {jQuery} $form Form container.
		 */
		updateGBBlockRatingColor: function( $form ) {

			$form
				.find( '.wpforms-field-rating-item svg' )
				.css( 'color', 'var( --wpforms-button-background-color )' );
		},

		/**
		 * Init Page Break fields.
		 *
		 * @since 1.8.1
		 */
		initPageBreakButtons: function() {

			$( '.wpforms-page-button' )
				.removeClass( 'wpforms-disabled' )
				.attr( 'aria-disabled', 'false' )
				.attr( 'aria-describedby', '' );
		},

		/**
		 * Handler for `wpformsCombinedUploadsSizeError` event.
		 * Accessibility enhancements to error container and submit button.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e         Event object.
		 * @param {jQuery} $form     Form object.
		 * @param {jQuery} $errorCnt Error container object.
		 */
		combinedUploadsSizeError: function( e, $form, $errorCnt ) {

			const formId = $form.data( 'formid' ),
				errormessage = $form.attr( 'aria-errormessage' ) || '',
				errorCntId = `wpforms-${formId}-footer-error`,
				$submitBtn = $form.find( '.wpforms-submit' );

			$form.attr( {
				'aria-invalid': 'true',
				'aria-errormessage': `${errormessage} ${errorCntId}`,
			} );

			$errorCnt.attr( {
				'role': 'alert',
				'id': errorCntId,
			} );

			// Add error message prefix.
			$errorCnt.find( '> .wpforms-hidden:first-child' ).remove();
			$errorCnt.prepend( `<span class="wpforms-hidden">${wpforms_settings.formErrorMessagePrefix}</span>` );

			// Instead of set the `disabled` property,
			// we must use `aria-disabled` and `aria-describedby` attributes in conduction with `wpforms-disabled` class.
			$submitBtn
				.prop( 'disabled', false )
				.addClass( 'wpforms-disabled' )
				.attr( 'aria-disabled', 'true' )
				.attr( 'aria-describedby', errorCntId );
		},

		/**
		 * Handler for `wpformsCombinedUploadsSizeOk` event.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e         Event object.
		 * @param {jQuery} $form     Form object.
		 * @param {jQuery} $errorCnt Error container object.
		 */
		combinedUploadsSizeOk: function( e, $form, $errorCnt ) {

			const $submitBtn = $form.find( '.wpforms-submit' );

			// Revert aria-* attributes to the normal state.
			$submitBtn
				.removeClass( 'wpforms-disabled' )
				.attr( 'aria-disabled', 'false' )
				.attr( 'aria-describedby', '' );
		},

		/**
		 * Handler for `wpformsFormSubmitButtonDisable` event.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e          Event object.
		 * @param {jQuery} $form      Form object.
		 * @param {jQuery} $submitBtn Submit button object.
		 */
		formSubmitButtonDisable: function( e, $form, $submitBtn ) {

			const disabledBtnDescId = $form.attr( 'id' ) + '-submit-btn-disabled';

			$submitBtn.before( `<div class="wpforms-hidden" id="${disabledBtnDescId}">${wpforms_settings.submitBtnDisabled}</div>` );

			$submitBtn
				.prop( 'disabled', false )
				.addClass( 'wpforms-disabled' )
				.attr( 'aria-disabled', 'true' )
				.attr( 'aria-describedby', disabledBtnDescId );
		},

		/**
		 * Handler for `wpformsFormSubmitButtonRestore` event.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e          Event object.
		 * @param {jQuery} $form      Form object.
		 * @param {jQuery} $submitBtn Submit button object.
		 */
		formSubmitButtonRestore: function( e, $form, $submitBtn ) {

			const disabledBtnDescId = $form.attr( 'id' ) + '-submit-btn-disabled';

			$form.find( '#' + disabledBtnDescId ).remove();

			$submitBtn
				.removeClass( 'wpforms-disabled' )
				.attr( 'aria-disabled', 'false' )
				.attr( 'aria-describedby', '' );
		},

		/**
		 * Disabled button click/keydown event handler.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e Event object.
		 */
		disabledButtonPress: function( e ) {

			const $submitBtn = $( this );

			if ( ! $submitBtn.hasClass( 'wpforms-disabled' ) ) {
				return;
			}

			if ( e.key === 'Enter' || e.type === 'click' ) {
				e.preventDefault();
				e.stopPropagation();
			}
		},

		/**
		 * Page change event handler.
		 *
		 * @since 1.8.1
		 *
		 * @param {object}  e        Event object.
		 * @param {integer} nextPage The next page number.
		 * @param {jQuery}  $form    Current form.
		 */
		pageChange: function( e, nextPage, $form ) {

			const $pageIndicator = $form.find( '.wpforms-page-indicator' );

			if ( ! wpforms_settings.indicatorStepsPattern || ! $pageIndicator.length ) {
				return;
			}

			const totalPages = $form.find( '.wpforms-page' ).length;
			let msg = wpforms_settings.indicatorStepsPattern;
			let pageTitle;

			msg = msg.replace( '{current}', nextPage ).replace( '{total}', totalPages );

			if ( $pageIndicator.hasClass( 'progress' ) ) {
				pageTitle = $pageIndicator.find( '.wpforms-page-indicator-page-title' ).data( `page-${nextPage}-title` );
			} else {
				pageTitle = $pageIndicator.find( `.wpforms-page-indicator-page-${nextPage} .wpforms-page-indicator-page-title` ).text();
			}

			msg = pageTitle ? pageTitle + '. ' + msg : msg;

			$pageIndicator.attr( 'aria-valuenow', nextPage );
			app.screenReaderAnnounce( msg, 'polite' );
		},

		/**
		 * Allows the screen reader to talk directly through the use of JS.
		 *
		 * @since 1.8.1
		 *
		 * @param {string} text     The message to be vocalised
		 * @param {string} priority Aria-live priority. "polite" (by default) or "assertive".
		 */
		screenReaderAnnounce: function( text, priority ) {

			const el = document.createElement( 'div' );
			const id = 'wpforms-screen-reader-announce-' + Date.now();

			el.setAttribute( 'id', id );
			el.setAttribute( 'aria-live', priority || 'polite' );
			el.classList.add( 'wpforms-screen-reader-announce' );

			let node = document.body.appendChild( el );

			setTimeout( function() {
				node.innerHTML = text;
			}, 100 );

			setTimeout( function() {
				document.body.removeChild( node );
			}, 1000 );
		},

		/**
		 * Add opacity to color string.
		 * Supports formats: RGB, RGBA, HEX, HEXA.
		 *
		 * If the given color has an alpha channel, the new alpha channel will be calculated according to the given opacity.
		 *
		 * @since 1.8.1
		 *
		 * @param {string} color   Color.
		 * @param {string} opacity Opacity.
		 *
		 * @returns {string} Color in RGBA format with added alpha channel according to given opacity.
		 */
		getColorWithOpacity: function( color, opacity ) {

			color = color.trim();

			const rgbArray = app.getColorAsRGBArray( color );

			if ( ! rgbArray ) {
				return color;
			}

			// Default opacity is 1.
			opacity = ! opacity || opacity.length === 0 ? '1' : opacity.toString();

			let alpha = rgbArray.length === 4 ? parseFloat( rgbArray[3] ) : 1;

			// Calculate new alpha value.
			let newAlpha = parseFloat( opacity ) * alpha;

			// Combine and return the RGBA color.
			return `rgba(${rgbArray[0]},${rgbArray[1]},${rgbArray[2]},${newAlpha})`.replace( /\s+/g, '' );
		},

		/**
		 * Remove opacity from the color value.
		 * Supports formats: RGB, RGBA, HEX, HEXA.
		 *
		 * @since 1.8.1
		 *
		 * @param {string} color Color.
		 *
		 * @returns {string} Color in RGB format.
		 */
		getSolidColor: function( color ) {

			color = color.trim();

			const rgbArray = app.getColorAsRGBArray( color );

			if ( ! rgbArray ) {
				return color;
			}

			// Combine and return the RGB color.
			return `rgb(${rgbArray[0]},${rgbArray[1]},${rgbArray[2]})`;
		},

		/**
		 * Check if the given color is a valid CSS color.
		 *
		 * @since 1.8.1
		 *
		 * @param {string} color Color.
		 *
		 * @returns {boolean} True if the given color is a valid CSS color.
		 */
		isValidColor: function( color ) {

			// Create temporary DOM element and use `style` property.
			const s = new Option().style;

			s.color = color;

			// Invalid color leads to the empty color property of DOM element style.
			return s.color !== '';
		},

		/**
		 * Get color as an array of RGB(A) values.
		 *
		 * @since 1.8.1
		 *
		 * @param {string} color Color.
		 *
		 * @returns {Array|boolean} Color as an array of RGBA values. False on error.
		 */
		getColorAsRGBArray: function( color ) {

			// Check if the given color is a valid CSS color.
			if ( ! app.isValidColor( color ) ) {
				return false;
			}

			// Remove # from the beginning of the string.
			color = color.replace( /^#/, '' );

			let rgba = color;
			let rgbArray;

			// Check if color is in HEX(A) format.
			let isHex = rgba.match( /[0-9a-f]{6,8}$/ig );

			if ( isHex ) {

				// Search and split HEX(A) color into an array of couples of chars.
				rgbArray    = rgba.match( /\w\w/g ).map( x => parseInt( x, 16 ) );
				rgbArray[3] = rgbArray[3] ? ( rgbArray[3] / 255 ).toFixed( 2 ) : 1;

			} else {
				rgbArray = rgba.split( '(' )[1].split( ')' )[0].split( ',' );
			}

			return rgbArray;
		},

		/**
		 * Get CSS variable value.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} style   Computed style object.
		 * @param {string} varName Style custom property name.
		 *
		 * @returns {string|null} CSS variable value;
		 */
		getCssVar: function( style, varName ) {

			if ( ! style || typeof style.getPropertyValue !== 'function' ) {
				return null;
			}

			let value = style.getPropertyValue( varName ).trim();

			if ( varName.includes( 'color' ) ) {
				value = value.replace( /\s/g, '' );
			}

			return value;
		},

		/**
		 * Get all CSS variables.
		 *
		 * @since 1.8.1
		 *
		 * @param {jQuery} $form Form OR any element inside the form.
		 *
		 * @returns {object} CSS variables;
		 */
		getCssVars: function( $form ) {

			if ( ! $form || ! $form.length ) {
				return null;
			}

			const $cont = $form.hasClass( 'wpforms-container' ) ? $form : $form.closest( '.wpforms-container' );
			const contStyle = getComputedStyle( $cont.get( 0 ) );
			const cssVars = wpforms_settings.css_vars;
			let vars = {};

			for ( var i = 0; i < cssVars.length; i++ ) {
				vars[ cssVars[ i ] ] = app.getCssVar( contStyle, '--wpforms-' + cssVars[ i ] );
			}

			return vars;
		},
	};

	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.FrontendModern.init();
