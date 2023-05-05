/* global wpforms_builder, WPFormsUtils */

;
var wpf = {

	cachedFields: {},
	savedState: false,
	initialSave: true,
	orders:  {
		fields: [],
		choices: {},
	},

	// This file contains a collection of utility functions.

	/**
	 * Start the engine.
	 *
	 * @since 1.0.1
	 */
	init: function() {

		wpf.bindUIActions();

		// Init Radio Group for Checkboxes.
		wpf.initRadioGroupForCheckboxes();

		jQuery( wpf.ready );
	},

	/**
	 * Document ready.
	 *
	 * @since 1.0.1
	 */
	ready: function() {

		// Load initial form saved state.
		wpf.savedState = wpf.getFormState( '#wpforms-builder-form' );

		// Save field and choice order for sorting later.
		wpf.setFieldOrders();
		wpf.setChoicesOrders();
	},

	/**
	 * Element bindings.
	 *
	 * @since 1.0.1
	 */
	bindUIActions: function() {

		// The following items should all trigger the fieldUpdate trigger.
		jQuery( document ).on( 'wpformsFieldAdd', wpf.setFieldOrders );
		jQuery( document ).on( 'wpformsFieldDelete', wpf.setFieldOrders );
		jQuery( document ).on( 'wpformsFieldMove', wpf.setFieldOrders );
		jQuery( document ).on( 'wpformsFieldAdd', wpf.setChoicesOrders );
		jQuery( document ).on( 'wpformsFieldChoiceAdd', wpf.setChoicesOrders );
		jQuery( document ).on( 'wpformsFieldChoiceDelete', wpf.setChoicesOrders );
		jQuery( document ).on( 'wpformsFieldChoiceMove', wpf.setChoicesOrders );
		jQuery( document ).on( 'wpformsFieldAdd', wpf.fieldUpdate );
		jQuery( document ).on( 'wpformsFieldDelete', wpf.fieldUpdate );
		jQuery( document ).on( 'wpformsFieldMove', wpf.fieldUpdate );
		jQuery( document ).on( 'focusout', '.wpforms-field-option-row-label input', wpf.fieldUpdate );
		jQuery( document ).on( 'wpformsFieldChoiceAdd', wpf.fieldUpdate );
		jQuery( document ).on( 'wpformsFieldChoiceDelete', wpf.fieldUpdate );
		jQuery( document ).on( 'wpformsFieldChoiceMove', wpf.fieldUpdate );
		jQuery( document ).on( 'wpformsFieldDynamicChoiceToggle', wpf.fieldUpdate );
		jQuery( document ).on( 'focusout', '.wpforms-field-option-row-choices input.label', wpf.fieldUpdate );
	},

	/**
	 * Store the order of the fields.
	 *
	 * @since 1.4.5
	 */
	setFieldOrders: function() {

		wpf.orders.fields = [];

		jQuery( '.wpforms-field-option' ).each( function() {
			wpf.orders.fields.push( jQuery( this ).data( 'field-id' ) );
		} );
	},

	/**
	 * Store the order of the choices for each field.
	 *
	 * @since 1.4.5
	 */
	setChoicesOrders: function() {

		wpf.orders.choices = {};

		jQuery( '.choices-list' ).each( function() {
			var fieldID = jQuery( this ).data( 'field-id' );
			wpf.orders.choices[ 'field_' + fieldID ] = [];
			jQuery( this ).find( 'li' ).each( function() {
				wpf.orders.choices[ 'field_' + fieldID ].push( jQuery( this ).data( 'key' ) );
			} );
		} );
	},

	/**
	 * Return the order of choices for a specific field.
	 *
	 * @since 1.4.5
	 *
	 * @param int id Field ID.
	 *
	 * @return array
	 */
	getChoicesOrder: function( id ) {

		var choices = [];

		jQuery( '#wpforms-field-option-' + id ).find( '.choices-list li' ).each( function() {
			choices.push( jQuery( this ).data( 'key' ) );
		} );

		return choices;
	},

	/**
	 * Maintain multiselect dropdown with search.
	 * If a multiple select has selected choices - hide a placeholder text.
	 * In case if select is empty - we return placeholder text back.
	 *
	 * @since 1.7.6
	 *
	 * @param {object} self Current object.
	 */
	initMultipleSelectWithSearch: function( self ) {

		const $element = jQuery( self.passedElement.element ),
			$input   = jQuery( self.input.element );

		if ( $element.prop( 'multiple' ) ) {

			// On init event.
			$input.data( 'placeholder', $input.attr( 'placeholder' ) );

			if ( self.getValue( true ).length ) {
				$input.removeAttr( 'placeholder' );
			}

			// On change event.
			$element.on( 'change', function() {

				self.getValue( true ).length ?
					$input.removeAttr( 'placeholder' ) :
					$input.attr( 'placeholder', $input.data( 'placeholder' ) );
			} );
		}
	},

	/**
	 * Trigger fired for all field update related actions.
	 *
	 * @since 1.0.1
	 */
	fieldUpdate: function() {

		var fields = wpf.getFields();

		jQuery( document ).trigger( 'wpformsFieldUpdate', [ fields ] );

		wpf.debug( 'fieldUpdate triggered' );
	},

	/**
	 * Dynamically get the fields from the current form state.
	 *
	 * @since 1.0.1
	 * @param array allowedFields
	 * @param bool useCache
	 * @return object
	 */
	getFields: function( allowedFields, useCache ) {

		useCache = useCache || false;

		if ( useCache && ! jQuery.isEmptyObject( wpf.cachedFields ) ) {

			// Use cache if told and cache is primed.
			var fields = jQuery.extend( {}, wpf.cachedFields );

			wpf.debug( 'getFields triggered (cached)' );

		} else {

			// Normal processing, get fields from builder and prime cache.
			var formData       = wpf.formObject( '#wpforms-field-options' ),
				fields         = formData.fields,
				fieldBlockList = [
					'captcha',
					'content',
					'divider',
					'entry-preview',
					'html',
					'internal-information',
					'layout',
					'pagebreak',
				];

			if ( ! fields ) {
				return false;
			}

			for ( var key in fields ) {
				if ( ! fields[key].type || jQuery.inArray( fields[key].type, fieldBlockList ) > -1 ) {
					delete fields[key];
				}
			}

			// Cache the all the fields now that they have been ordered and initially processed.
			wpf.cachedFields = jQuery.extend( {}, fields );

			wpf.debug( 'getFields triggered' );
		}

		// If we should only return specific field types, remove the others.
		if ( allowedFields && allowedFields.constructor === Array ) {
			for ( var key in fields ) {
				if ( jQuery.inArray( fields[key].type, allowedFields ) === -1 ) {
					delete fields[key];
				}
			}
		}

		return fields;
	},

	/**
	 * Get field settings object.
	 *
	 * @since 1.4.5
	 *
	 * @param int id Field ID.
	 *
	 * @return object
	 */
	getField: function( id ) {

		var field = wpf.formObject( '#wpforms-field-option-' + id );

		return field.fields[ Object.keys( field.fields )[0] ];
	},

	/**
	 * Toggle the loading state/indicator of a field option.
	 *
	 * @since 1.2.8
	 *
	 * @param {mixed}   option jQuery object, or DOM element selector.
	 * @param {boolean} unload True if you need to unload spinner, and vice versa.
	 */
	fieldOptionLoading: function( option, unload ) {

		var $option = jQuery( option ),
			$label  = $option.find( 'label' ),
			spinner = '<i class="wpforms-loading-spinner wpforms-loading-inline"></i>';

		unload  = typeof unload !== 'undefined';

		if ( unload ) {
			$label.find( '.wpforms-loading-spinner' ).remove();
			$label.find( '.wpforms-help-tooltip' ).show();
			$option.find( 'input,select,textarea' ).prop( 'disabled', false );
		} else {
			$label.append( spinner );
			$label.find( '.wpforms-help-tooltip' ).hide();
			$option.find( 'input,select,textarea' ).prop( 'disabled', true );
		}
	},

	/**
	 * Get form state.
	 *
	 * @since 1.3.8
	 * @param object el
	 */
	getFormState: function( el ) {

		// Serialize tested the most performant string we can use for
		// comparisons.
		return jQuery( el ).serialize();
	},

	/**
	 * Remove items from an array.
	 *
	 * @since 1.0.1
	 * @param array array
	 * @param mixed item index/key
	 * @return array
	 */
	removeArrayItem: function( array, item ) {

		var removeCounter = 0;

		for ( var index = 0; index < array.length; index++ ) {
			if ( array[index] === item ) {
				array.splice( index, 1 );
				removeCounter++;
				index--;
			}
		}

		return removeCounter;
	},

	/**
	 * Sanitize string.
	 *
	 * @since 1.0.1
	 * @deprecated 1.2.8
	 *
	 * @param {string} str String to sanitize.
	 *
	 * @returns {string} String after sanitization.
	 */
	sanitizeString: function( str ) {

		if ( typeof str === 'string' || str instanceof String ) {
			return str.trim();
		}
		return str;
	},

	/**
	 * Update query string in URL.
	 *
	 * @since 1.0.0
	 */
	updateQueryString: function( key, value, url ) {

		if ( ! url ) {
			url = window.location.href;
		}

		var re = new RegExp( '([?&])' + key + '=.*?(&|#|$)(.*)', 'gi' ),
			hash;

		if ( re.test( url ) ) {
			if ( typeof value !== 'undefined' && value !== null )
				return url.replace( re, '$1' + key + '=' + value + '$2$3' );
			else {
				hash = url.split( '#' );
				url = hash[0].replace( re, '$1$3' ).replace( /(&|\?)$/, '' );
				if ( typeof hash[1] !== 'undefined' && hash[1] !== null )
					url += '#' + hash[1];
				return url;
			}
		} else {
			if ( typeof value !== 'undefined' && value !== null ) {
				var separator = url.indexOf( '?' ) !== -1 ? '&' : '?';
				hash = url.split( '#' );
				url = hash[0] + separator + key + '=' + value;
				if ( typeof hash[1] !== 'undefined' && hash[1] !== null )
					url += '#' + hash[1];
				return url;
			}
			else
				return url;
		}
	},

	/**
	 * Get query string in a URL.
	 *
	 * @since 1.0.0
	 */
	getQueryString: function( name ) {

		var match = new RegExp( '[?&]' + name + '=([^&]*)' ).exec( window.location.search );
		return match && decodeURIComponent( match[1].replace( /\+/g, ' ' ) );
	},

	/**
	 * Remove defined query parameter in the current URL.
	 *
	 * @see https://gist.github.com/simonw/9445b8c24ddfcbb856ec#gistcomment-3117674
	 *
	 * @since 1.5.8
	 *
	 * @param {string} name The name of the parameter to be removed.
	 */
	removeQueryParam: function( name ) {

		if ( wpf.getQueryString( name ) ) {
			var replace = '[\\?&]' + name + '=[^&]+',
				re      = new RegExp( replace );

			history.replaceState && history.replaceState(
				null, '', location.pathname + location.search.replace( re, '' ).replace( /^&/, '?' ) + location.hash
			);
		}
	},

	/**
	 * Is number?
	 *
	 * @since 1.2.3
	 *
	 * @param {number|string} n Number to check.
	 *
	 * @returns {boolean} Whether this is a number.
	 */
	isNumber: function( n ) {
		return ! isNaN( parseFloat( n ) ) && isFinite( n );
	},

	/**
	 * Sanitize amount and convert to standard format for calculations.
	 *
	 * @since 1.2.6
	 *
	 * @param {string} amount Price amount to sanitize.
	 *
	 * @returns {string} Sanitized amount.
	 */
	amountSanitize: function( amount ) {

		// Convert to string and allow only numbers, dots and commas.
		amount = String( amount ).replace( /[^0-9.,]/g, '' );

		if ( wpforms_builder.currency_decimal === ',' ) {
			if ( wpforms_builder.currency_thousands === '.' && amount.indexOf( wpforms_builder.currency_thousands ) !== -1 ) {
				amount = amount.replace( new RegExp( '\\' + wpforms_builder.currency_thousands, 'g' ), '' );
			} else if ( wpforms_builder.currency_thousands === '' && amount.indexOf( '.' ) !== -1 ) {
				amount = amount.replace( /\./g, '' );
			}
			amount = amount.replace( wpforms_builder.currency_decimal, '.' );
		} else if ( wpforms_builder.currency_thousands === ',' && ( amount.indexOf( wpforms_builder.currency_thousands ) !== -1 ) ) {
			amount = amount.replace( new RegExp( '\\' + wpforms_builder.currency_thousands, 'g' ), '' );
		}

		return wpf.numberFormat( amount, wpforms_builder.currency_decimals, '.', '' );
	},

	/**
	 * Format amount.
	 *
	 * @since 1.2.6
	 *
	 * @param {string} amount Price amount to format.
	 *
	 * @returns {string} Formatted amount.
	 */
	amountFormat: function( amount ) {

		amount = String( amount );

		// Format the amount
		if ( wpforms_builder.currency_decimal === ',' && ( amount.indexOf( wpforms_builder.currency_decimal ) !== -1 ) ) {
			var sepFound = amount.indexOf( wpforms_builder.currency_decimal );

			amount = amount.substr( 0, sepFound ) + '.' + amount.substr( sepFound + 1, amount.length - 1 );
		}

		// Strip , from the amount (if set as the thousand separator)
		if ( wpforms_builder.currency_thousands === ',' && ( amount.indexOf( wpforms_builder.currency_thousands ) !== -1 ) ) {
			amount = amount.replace( /,/g, '' );
		}

		if ( wpf.empty( amount ) ) {
			amount = 0;
		}

		return wpf.numberFormat( amount, wpforms_builder.currency_decimals, wpforms_builder.currency_decimal, wpforms_builder.currency_thousands );
	},

	/**
	 * Format amount with currency symbol.
	 *
	 * @since 1.6.2
	 *
	 * @param {string} amount Amount to format.
	 *
	 * @returns {string} Formatted amount (for instance $ 128.00).
	 */
	amountFormatCurrency: function( amount ) {

		var sanitized  = wpf.amountSanitize( amount ),
			formatted  = wpf.amountFormat( sanitized ),
			result;

		if ( wpforms_builder.currency_symbol_pos === 'right' ) {
			result = formatted + ' ' + wpforms_builder.currency_symbol;
		} else {
			result = wpforms_builder.currency_symbol + ' ' + formatted;
		}

		return result;
	},

	/**
	 * Format number.
	 *
	 * @see http://locutus.io/php/number_format/
	 *
	 * @since 1.2.6
	 *
	 * @param {string} number       Number to format.
	 * @param {number} decimals     How many decimals should be there.
	 * @param {string} decimalSep   What is the decimal separator.
	 * @param {string} thousandsSep What is the thousand separator.
	 *
	 * @returns {string} Formatted number.
	 */
	numberFormat: function( number, decimals, decimalSep, thousandsSep ) {

		number = ( number + '' ).replace( /[^0-9+\-Ee.]/g, '' );
		var n = ! isFinite( +number ) ? 0 : +number;
		var prec = ! isFinite( +decimals ) ? 0 : Math.abs( decimals );
		var sep = ( typeof thousandsSep === 'undefined' ) ? ',' : thousandsSep;
		var dec = ( typeof decimalSep === 'undefined' ) ? '.' : decimalSep;
		var s = '';

		var toFixedFix = function( n, prec ) {
			var k = Math.pow( 10, prec );
			return '' + ( Math.round( n * k ) / k ).toFixed( prec );
		};

		// @todo: for IE parseFloat(0.55).toFixed(0) = 0;
		s = ( prec ? toFixedFix( n, prec ) : '' + Math.round( n ) ).split( '.' );
		if ( s[ 0 ].length > 3 ) {
			s[ 0 ] = s[ 0 ].replace( /\B(?=(?:\d{3})+(?!\d))/g, sep );
		}
		if ( ( s[ 1 ] || '' ).length < prec ) {
			s[ 1 ] = s[ 1 ] || '';
			s[ 1 ] += new Array( prec - s[ 1 ].length + 1 ).join( '0' );
		}

		return s.join( dec );
	},

	/**
	 * Empty check similar to PHP.
	 *
	 * @link http://locutus.io/php/empty/
	 * @since 1.2.6
	 */
	empty: function( mixedVar ) {

		var undef;
		var key;
		var i;
		var len;
		var emptyValues = [ undef, null, false, 0, '', '0' ];

		for ( i = 0, len = emptyValues.length; i < len; i++ ) {
			if ( mixedVar === emptyValues[i] ) {
				return true;
			}
		}

		if ( typeof mixedVar === 'object' ) {
			for ( key in mixedVar ) {
				if ( mixedVar.hasOwnProperty( key ) ) {
					return false;
				}
			}
			return true;
		}

		return false;
	},

	/**
	 * Debug output helper.
	 *
	 * @since 1.3.8
	 *
	 * @param {string|integer|boolean|Array|object} msg Debug message (any data).
	 */
	debug: function( ...msg ) {

		if ( ! wpf.isDebug() ) {
			return;
		}

		console.log( '%cWPForms Debug: ', 'color: #cd6622;', ...msg );
	},

	/**
	 * Is debug mode.
	 *
	 * @since 1.3.8
	 */
	isDebug: function() {
		return ( ( window.location.hash && '#wpformsdebug' === window.location.hash ) || wpforms_builder.debug );
	},

	/**
	 * Focus the input/textarea and put the caret at the end of the text.
	 *
	 * @since 1.4.1
	 */
	focusCaretToEnd: function( el ) {
		el.trigger( 'focus' );
		var $thisVal = el.val();
		el.val( '' ).val( $thisVal );
	},

	/**
	 * Creates a object from form elements.
	 *
	 * @since 1.4.5
	 */
	formObject: function( el ) {

		var form         = jQuery( el ),
			fields       = form.find( '[name]' ),
			json         = {},
			arraynames   = {};

		for ( var v = 0; v < fields.length; v++ ) {

			var field     = jQuery( fields[v] ),
				name      = field.prop( 'name' ).replace( /\]/gi, '' ).split( '[' ),
				value     = field.val(),
				lineconf  = {};

			if ( ( field.is( ':radio' ) || field.is( ':checkbox' ) ) && ! field.is( ':checked' ) ) {
				continue;
			}
			for ( var i = name.length - 1; i >= 0; i-- ) {
				var nestname = name[i];
				if ( typeof nestname === 'undefined' ) {
					nestname = '';
				}
				if ( nestname.length === 0 ){
					lineconf = [];
					if ( typeof arraynames[name[i - 1]] === 'undefined' )  {
						arraynames[name[i - 1]] = 0;
					} else {
						arraynames[name[i - 1]] += 1;
					}
					nestname = arraynames[name[i - 1]];
				}
				if ( i === name.length - 1 ) {
					if ( value ) {
						if ( value === 'true' ) {
							value = true;
						} else if ( value === 'false' ) {
							value = false;
						} else if ( ! isNaN( parseFloat( value ) ) && parseFloat( value ).toString() === value ) {
							value = parseFloat( value );
						} else if ( typeof value === 'string' && ( value.substr( 0, 1 ) === '{' || value.substr( 0, 1 ) === '[' ) ) {
							try {
								value = JSON.parse( value );
							} catch ( e ) {}
						} else if ( typeof value === 'object' && value.length && field.is( 'select' ) ) {
							var newValue = {};
							for ( var i = 0; i < value.length; i++ ) {
								newValue[ 'n' + i ] = value[ i ];
							}
							value = newValue;
						}
					}
					lineconf[nestname] = value;
				} else {
					var newobj = lineconf;
					lineconf = {};
					lineconf[nestname] = newobj;
				}
			}
			jQuery.extend( true, json, lineconf );
		}

		return json;
	},

	/**
	 * Initialize WPForms admin area tooltips.
	 *
	 * @since 1.4.8
	 */
	initTooltips: function() {

		if ( typeof jQuery.fn.tooltipster === 'undefined' ) {
			return;
		}

		jQuery( '.wpforms-help-tooltip' ).tooltipster( {
			contentAsHTML: true,
			position: 'right',
			maxWidth: 300,
			multiple: true,
			interactive: true,
			debug: false,
			IEmin: 11,
		} );
	},

	/**
	 * Restore WPForms admin area tooltip's title.
	 *
	 * @since 1.6.5
	 *
	 * @param {mixed} $scope Searching scope.
	 */
	restoreTooltips: function( $scope ) {

		$scope = typeof $scope !== 'undefined' && $scope && $scope.length > 0 ? $scope.find( '.wpforms-help-tooltip' ) : jQuery( '.wpforms-help-tooltip' );
		$scope.each( function() {
			var $this = jQuery( this );
			if ( jQuery.tooltipster.instances( this ).length !== 0 ) {

				// Restoring title.
				$this.attr( 'title', $this.tooltipster( 'content' ) );
			}
		} );
	},

	/**
	 * Validate a URL.
	 * source: `https://github.com/segmentio/is-url/blob/master/index.js`
	 *
	 * @since 1.5.8
	 *
	 * @param {string} url URL for checking.
	 *
	 * @returns {boolean} True if `url` is a valid URL.
	 */
	isURL: function( url ) {

		/**
		 * RegExps.
		 * A URL must match #1 and then at least one of #2/#3.
		 * Use two levels of REs to avoid REDOS.
		 */
		var protocolAndDomainRE  = /^(?:http(?:s?):)?\/\/(\S+)/;
		var localhostDomainRE    = /^localhost[\:?\d]*(?:[^\:?\d]\S*)?$/;
		var nonLocalhostDomainRE = /^[^\s\.]+\.\S{2,}$/;

		if ( typeof url !== 'string' ) {
			return false;
		}

		var match = url.match( protocolAndDomainRE );
		if ( ! match ) {
			return false;
		}

		var everythingAfterProtocol = match[1];
		if ( ! everythingAfterProtocol ) {
			return false;
		}

		if ( localhostDomainRE.test( everythingAfterProtocol ) || nonLocalhostDomainRE.test( everythingAfterProtocol ) ) {
			return true;
		}

		return false;
	},

	/**
	 * Sanitize HTML.
	 * Uses: `https://github.com/cure53/DOMPurify`
	 *
	 * @since 1.5.9
	 * @since 1.7.8 Introduced optional allowed parameter.
	 *
	 * @param {string}           string  HTML to sanitize.
	 * @param {undefined|Array}  allowed Array of allowed HTML tags.
	 *
	 * @returns {string} Sanitized HTML.
	 */
	sanitizeHTML: function( string, allowed ) {

		var purify = window.DOMPurify;

		if ( typeof purify === 'undefined' || typeof string === 'undefined' ) {
			return string;
		}

		if ( typeof string !== 'string' ) {
			string = string.toString();
		}

		const purifyOptions = {
			ADD_ATTR: [ 'target' ],
		};

		if ( typeof allowed !== 'undefined' ) {
			purifyOptions.ALLOWED_TAGS = allowed;
		}

		return purify.sanitize( string, purifyOptions ).trim();
	},

	/**
	 * Encode HTML entities.
	 * Uses: `https://stackoverflow.com/a/18750001/9745718`
	 *
	 * @since 1.6.3
	 *
	 * @param {string} string HTML to sanitize.
	 *
	 * @returns {string} String with encoded HTML entities.
	 */
	encodeHTMLEntities: function( string ) {

		if ( typeof string !== 'string' ) {
			string = string.toString();
		}

		return string.replace( /[\u00A0-\u9999<>&]/gim, function( i ) {

			return '&#' + i.charCodeAt( 0 ) + ';';
		} );
	},

	/**
	 * Radio Group for Checkboxes.
	 *
	 * @since 1.6.6
	 */
	initRadioGroupForCheckboxes: function() {

		var $ = jQuery;

		$( document ).on( 'change', 'input[type="checkbox"].wpforms-radio-group', function() {

			var $input  = $( this ),
				inputId = $input.attr( 'id' );

			if ( ! $input.prop( 'checked' ) ) {
				return;
			}

			var groupName = $input.data( 'radio-group' ),
				$group    = $( '.wpforms-radio-group-' + groupName ),
				$item;

			$group.each( function() {

				$item = $( this );
				if ( $item.attr( 'id' ) !== inputId ) {
					$item.prop( 'checked', false );
				}
			} );
		} );
	},

	/**
	 * Pluck a certain field out of each object in a list.
	 *
	 * JS implementation of the `wp_list_pluck()`.
	 *
	 * @since 1.6.8
	 *
	 * @param {Array}  arr    Array of objects.
	 * @param {string} column Column.
	 *
	 * @returns {Array} Array with extracted column values.
	 */
	listPluck: function( arr, column ) {

		return arr.map( function( x ) {

			if ( typeof x !== 'undefined' ) {
				return x[ column ];
			}

			return x;
		} );
	},

	/**
	 * Wrapper to trigger a native or custom event and return the event object.
	 *
	 * @since 1.7.5
	 * @since 1.7.6 Deprecated.
	 *
	 * @deprecated Use `WPFormsUtils.triggerEvent` instead.
	 *
	 * @param {jQuery} $element  Element to trigger event on.
	 * @param {string} eventName Event name to trigger (custom or native).
	 *
	 * @returns {Event} Event object.
	 */
	triggerEvent: function( $element, eventName ) {

		console.warn( 'WARNING! Function "wpf.triggerEvent( $element, eventName )" has been deprecated, please use the new "WPFormsUtils.triggerEvent( $element, eventName, args )" function instead!' );

		return WPFormsUtils.triggerEvent( $element, eventName );
	},

	/**
	 * Automatically add paragraphs to the text.
	 *
	 * JS implementation of the `wpautop()`.
	 *
	 * @see https://github.com/andymantell/node-wpautop/blob/master/lib/wpautop.js
	 *
	 * @since 1.7.7
	 *
	 * @param {string} pee Text to be replaced.
	 * @param {boolean} br Whether remaining \n characters should be replaced with <br />.
	 *
	 * @returns {string} Text with replaced paragraphs.
	 */
	wpautop: function( pee, br = true ) { // eslint-disable-line max-lines-per-function, complexity

		let preTags = new Map();
		let _autopNewlinePreservationHelper = function( matches ) {

			return matches[0].replace( '\n', '<WPPreserveNewline />' );
		};

		if ( ( typeof pee ) !== 'string' && ! ( pee instanceof String ) ) {
			return pee;
		}

		if ( pee.trim() === '' ) {
			return '';
		}

		pee = pee + '\n'; // Just to make things a little easier, pad the end.

		if ( pee.indexOf( '<pre' ) > -1 ) {
			let peeParts = pee.split( '</pre>' ),
				lastPee  = peeParts.pop();

			pee = '';

			peeParts.forEach(
				function( peePart, index ) {

					const start = peePart.indexOf( '<pre' );

					// Malformed html?
					if ( start === -1 ) {
						pee += peePart;
						return;
					}

					let name      = '<pre wp-pre-tag-' + index + '></pre>';
					preTags[name] = peePart.substring( start ) + '</pre>';
					pee          += peePart.substring( 0, start ) + name;

				}
			);

			pee += lastPee;
		}

		pee = pee.replace( /<br \/>\s*<br \/>/, '\n\n' );

		// Space things out a little.
		let allblocks = '(?:table|thead|tfoot|caption|col|colgroup|tbody|tr|td|th|div|dl|dd|dt|ul|ol|li|pre|form|map|area|blockquote|address|math|style|p|h[1-6]|hr|fieldset|legend|section|article|aside|hgroup|header|footer|nav|figure|figcaption|details|menu|summary)';

		pee = pee.replace( new RegExp( '(<' + allblocks + '[^>]*>)', 'gmi' ), '\n$1' );
		pee = pee.replace( new RegExp( '(</' + allblocks + '>)', 'gmi' ), '$1\n\n' );
		pee = pee.replace( /\r\n|\r/, '\n' ); // cross-platform newlines.

		if ( pee.indexOf( '\n' ) === 0 ) {
			pee = pee.substring( 1 );
		}

		if ( pee.indexOf( '<option' ) > -1 ) {

			// no P/BR around option.
			pee = pee.replace( /(?=(\s*))\2<option'/gmi, '<option' );
			pee = pee.replace( /<\/option>\s*/gmi, '</option>' );
		}

		if ( pee.indexOf( '</object>' ) > -1 ) {

			// no P/BR around param and embed.
			pee = pee.replace( /(<object[^>]*>)\s*/gmi, '$1' );
			pee = pee.replace( /(?=(\s*))\2<\/object>/gmi, '</object>' );
			pee = pee.replace( /(?=(\s*))\2(<\/?(?:param|embed)[^>]*>)((?=(\s*))\2)/gmi, '$1' );
		}

		/* eslint-disable no-useless-escape */

		if ( pee.indexOf( '<source' ) > -1 || pee.indexOf( '<track' ) > -1 ) {

			// no P/BR around source and track.
			pee = pee.replace( /([<\[](?:audio|video)[^>\]]*[>\]])\s*/gmi, '$1' );
			pee = pee.replace( /(?=(\s*))\2([<\[]\/(?:audio|video)[>\]])/gmi, '$1' );
			pee = pee.replace( /(?=(\s*))\2(<(?:source|track)[^>]*>)(?=(\s*))\2/gmi, '$1' );
		}

		pee = pee.replace( /\n\n+/gmi, '\n\n' ); // take care of duplicates.

		// make paragraphs, including one at the end.
		let pees = pee.split( /\n\s*\n/ );

		pee = '';

		pees.forEach(
			function( tinkle ) {
				pee += '<p>' + tinkle.replace( /^(?:\s+|\s+)$/g, '' ) + '</p>\n';
			}
		);

		pee = pee.replace( /<p>\s*<\/p>/gmi, '' ); // under certain strange conditions it could create a P of entirely whitespace.
		pee = pee.replace( /<p>([^<]+)<\/(div|address|form)>/gmi, '<p>$1</p></$2>' );
		pee = pee.replace( new RegExp( '<p>\s*(</?' + allblocks + '[^>]*>)\s*</p>', 'gmi' ), '$1', pee ); // don't pee all over a tag.
		pee = pee.replace( /<p>(<li.+?)<\/p>/gmi, '$1' ); // problem with nested lists.
		pee = pee.replace( /<p><blockquote([^>]*)>/gmi, '<blockquote$1><p>' );
		pee = pee.replace( /<\/blockquote><\/p>/gmi, '</p></blockquote>' );
		pee = pee.replace( new RegExp( '<p>\s*(</?' + allblocks + '[^>]*>)', 'gmi' ), '$1' );
		pee = pee.replace( new RegExp( '(</?' + allblocks + '[^>]*>)\s*</p>', 'gmi' ), '$1' );

		if ( br ) {
			pee = pee.replace( /<(script|style)(?:.|\n)*?<\/\\1>/gmi, _autopNewlinePreservationHelper ); // /s modifier from php PCRE regexp replaced with (?:.|\n).
			pee = pee.replace( /(<br \/>)?((?=(\s*))\2)\n/gmi, '<br />\n' ); // optionally make line breaks.
			pee = pee.replace( '<WPPreserveNewline />', '\n' );
		}

		pee = pee.replace( new RegExp( '(</?' + allblocks + '[^>]*>)\s*<br />', 'gmi' ), '$1' );
		pee = pee.replace( /<br \/>(\s*<\/?(?:p|li|div|dl|dd|dt|th|pre|td|ul|ol)[^>]*>)/gmi, '$1' );
		pee = pee.replace( /\n<\/p>$/gmi, '</p>' );

		/* esline-enable */

		if ( Object.keys( preTags ).length ) {
			pee = pee.replace(
				new RegExp( Object.keys( preTags ).join( '|' ), 'gi' ),
				function( matched ) {
					return preTags[matched];
				}
			);
		}

		return pee;
	},
};

wpf.init();
