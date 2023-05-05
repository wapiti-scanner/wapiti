'use strict';

( function() {

	/**
	 * Predefine hint text to display.
	 *
	 * @since 1.5.6
	 * @since 1.6.4 Added a new macros - {remaining}.
	 *
	 * @param {string} hintText Hint text.
	 * @param {number} count Current count.
	 * @param {number} limit Limit to.
	 *
	 * @returns {string} Predefined hint text.
	 */
	function renderHint( hintText, count, limit ) {

		return hintText.replace( '{count}', count ).replace( '{limit}', limit ).replace( '{remaining}', limit - count );
	}

	/**
	 * Create HTMLElement hint element with text.
	 *
	 * @since 1.5.6
	 *
	 * @param {number} formId Form id.
	 * @param {number} fieldId Form field id.
	 * @param {string} text Text to hint element.
	 *
	 * @returns {object} HTMLElement hint element with text.
	 */
	function createHint( formId, fieldId, text ) {

		var hint = document.createElement( 'div' );
		hint.classList.add( 'wpforms-field-limit-text' );
		hint.id = 'wpforms-field-limit-text-' + formId + '-' + fieldId;
		hint.setAttribute( 'aria-live', 'polite' );
		hint.textContent = text;

		return hint;
	}

	/**
	 * Keyup/Keydown event higher order function for characters limit.
	 *
	 * @since 1.5.6
	 *
	 * @param {object} hint HTMLElement hint element.
	 * @param {number} limit Max allowed number of characters.
	 *
	 * @returns {Function} Handler function.
	 */
	function checkCharacters( hint, limit ) {

		return function( e ) {

			hint.textContent = renderHint(
				window.wpforms_settings.val_limit_characters,
				this.value.length,
				limit
			);
		};
	}

	/**
	 * Count words in the string.
	 *
	 * @since 1.6.2
	 *
	 * @param {string} string String value.
	 *
	 * @returns {number} Words count.
	 */
	function countWords( string ) {

		if ( typeof string !== 'string' ) {
			return 0;
		}

		if ( ! string.length ) {
			return 0;
		}

		[
			/([A-Z]+),([A-Z]+)/gi,
			/([0-9]+),([A-Z]+)/gi,
			/([A-Z]+),([0-9]+)/gi,
		].forEach( function( pattern ) {
			string = string.replace( pattern, '$1, $2' );
		} );

		return string.split( /\s+/ ).length;
	}

	/**
	 * Keyup/Keydown event higher order function for words limit.
	 *
	 * @since 1.5.6
	 *
	 * @param {object} hint HTMLElement hint element.
	 * @param {number} limit Max allowed number of characters.
	 *
	 * @returns {Function} Handler function.
	 */
	function checkWords( hint, limit ) {

		return function( e ) {

			var value = this.value.trim(),
				words = countWords( value );

			hint.textContent = renderHint(
				window.wpforms_settings.val_limit_words,
				words,
				limit
			);

			// We should prevent the keys: Enter, Space, Comma.
			if ( [ 13, 32, 188 ].indexOf( e.keyCode ) > -1 && words >= limit ) {
				e.preventDefault();
			}
		};
	}

	/**
	 * Get passed text from clipboard.
	 *
	 * @since 1.5.6
	 *
	 * @param {ClipboardEvent} e Clipboard event.
	 *
	 * @returns {string} Text from clipboard.
	 */
	function getPastedText( e ) {

		if ( window.clipboardData && window.clipboardData.getData ) { // IE

			return window.clipboardData.getData( 'Text' );
		} else if ( e.clipboardData && e.clipboardData.getData ) {

			return e.clipboardData.getData( 'text/plain' );
		}
	}

	/**
	 * Paste event higher order function for characters limit.
	 *
	 * @since 1.6.7.1
	 *
	 * @param {number} limit Max allowed number of characters.
	 *
	 * @returns {Function} Event handler.
	 */
	function pasteText( limit ) {

		return function( e ) {

			e.preventDefault();

			var pastedText = getPastedText( e ),
				newPosition = this.selectionStart + pastedText.length,
				newText = this.value.substring( 0, this.selectionStart ) + pastedText + this.value.substring( this.selectionStart );

			this.value = newText.substring( 0, limit );
			this.setSelectionRange( newPosition, newPosition );
		};
	}

	/**
	 * Limit string length to a certain number of words, preserving line breaks.
	 *
	 * @since 1.6.8
	 *
	 * @param {string} text  Text.
	 * @param {number} limit Max allowed number of words.
	 *
	 * @returns {string} Text with the limited number of words.
	 */
	function limitWords( text, limit ) {

		var separators,
			newTextArray,
			result = '';

		// Regular expression pattern: match any space character.
		var regEx = /\s+/g;

		// Store separators for further join.
		separators = text.trim().match( regEx ) || [];

		// Split the new text by regular expression.
		newTextArray = text.split( regEx );

		// Limit the number of words.
		newTextArray.splice( limit, newTextArray.length );

		// Join the words together using stored separators.
		for ( var i = 0; i < newTextArray.length; i++ ) {
			result += newTextArray[ i ] + ( separators[ i ] || '' );
		}

		return result.trim();
	}

	/**
	 * Paste event higher order function for words limit.
	 *
	 * @since 1.5.6
	 *
	 * @param {number} limit Max allowed number of words.
	 *
	 * @returns {Function} Event handler.
	 */
	function pasteWords( limit ) {

		return function( e ) {

			e.preventDefault();

			var pastedText = getPastedText( e ),
				newPosition = this.selectionStart + pastedText.length,
				newText = this.value.substring( 0, this.selectionStart ) + pastedText + this.value.substring( this.selectionStart );

			this.value = limitWords( newText, limit );
			this.setSelectionRange( newPosition, newPosition );
		};
	}

	/**
	 * Array.form polyfill.
	 *
	 * @since 1.5.6
	 *
	 * @param {object} el Iterator.
	 *
	 * @returns {object} Array.
	 */
	function arrFrom( el ) {

		return [].slice.call( el );
	}

	/**
	 * DOMContentLoaded handler.
	 *
	 * @since 1.5.6
	 */
	function ready() {

		arrFrom( document.querySelectorAll( '.wpforms-limit-characters-enabled' ) )
			.map(
				function( e ) {

					var limit = parseInt( e.dataset.textLimit, 10 ) || 0;
					e.value = e.value.slice( 0, limit );
					var hint = createHint(
						e.dataset.formId,
						e.dataset.fieldId,
						renderHint(
							window.wpforms_settings.val_limit_characters,
							e.value.length,
							limit
						)
					);
					var fn = checkCharacters( hint, limit );
					e.parentNode.appendChild( hint );

					e.addEventListener( 'keydown', fn );
					e.addEventListener( 'keyup', fn );
					e.addEventListener( 'paste', pasteText( limit ) );
				}
			);

		arrFrom( document.querySelectorAll( '.wpforms-limit-words-enabled' ) )
			.map(
				function( e ) {

					var limit = parseInt( e.dataset.textLimit, 10 ) || 0;

					e.value = limitWords( e.value, limit );

					var hint = createHint(
						e.dataset.formId,
						e.dataset.fieldId,
						renderHint(
							window.wpforms_settings.val_limit_words,
							countWords( e.value.trim() ),
							limit
						)
					);
					var fn = checkWords( hint, limit );
					e.parentNode.appendChild( hint );

					e.addEventListener( 'keydown', fn );
					e.addEventListener( 'keyup', fn );
					e.addEventListener( 'paste', pasteWords( limit ) );
				}
			);
	}

	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', ready );
	} else {
		ready();
	}

}() );
