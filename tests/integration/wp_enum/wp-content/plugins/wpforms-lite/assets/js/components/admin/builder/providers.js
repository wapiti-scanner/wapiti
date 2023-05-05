/* global wpforms_builder, wpforms_builder_providers, wpf */

var WPForms = window.WPForms || {};
WPForms.Admin = WPForms.Admin || {};
WPForms.Admin.Builder = WPForms.Admin.Builder || {};

/**
 * WPForms Providers module.
 *
 * @since 1.4.7
 */
WPForms.Admin.Builder.Providers = WPForms.Admin.Builder.Providers || ( function( document, window, $ ) {

	'use strict';

	/**
	 * Private functions and properties.
	 *
	 * @since 1.4.7
	 *
	 * @type {Object}
	 */
	var __private = {

		/**
		 * Internal cache storage, do not use it directly, but app.cache.{(get|set|delete|clear)()} instead.
		 * Key is the provider slug, value is a Map, that will have its own key as a connection id (or not).
		 *
		 * @since 1.4.7
		 *
		 * @type {Object.<string, Map>}
		 */
		cache: {},

		/**
		 * Config contains all configuration properties.
		 *
		 * @since 1.4.7
		 *
		 * @type {Object.<string, *>}
		 */
		config: {

			/**
			 * List of default templates that should be compiled.
			 *
			 * @since 1.4.7
			 *
			 * @type {string[]}
			 */
			templates: [
				'wpforms-providers-builder-content-connection-fields',
				'wpforms-providers-builder-content-connection-conditionals',
			],
		},

		/**
		 * Form fields for the current state.
		 *
		 * @since 1.6.1.2
		 *
		 * @type {object}
		 */
		fields: {},
	};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.4.7
	 *
	 * @type {Object}
	 */
	var app = {

		/**
		 * Panel holder.
		 *
		 * @since 1.5.9
		 *
		 * @type {object}
		 */
		panelHolder: {},

		/**
		 * Form holder.
		 *
		 * @since 1.4.7
		 *
		 * @type {object}
		 */
		form: $( '#wpforms-builder-form' ),

		/**
		 * Spinner HTML.
		 *
		 * @since 1.4.7
		 *
		 * @type {object}
		 */
		spinner: '<i class="wpforms-loading-spinner wpforms-loading-inline"></i>',

		/**
		 * All ajax requests are grouped together with own properties.
		 *
		 * @since 1.4.7
		 */
		ajax: {

			/**
			 * Merge custom AJAX data object with defaults.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider
			 *
			 * @param {string} provider Current provider slug.
			 * @param {object} custom Ajax data object with custom settings.
			 *
			 * @returns {object} Ajax data.
			 */
			_mergeData: function( provider, custom ) {

				var data = {
					id: app.form.data( 'id' ),
					// eslint-disable-next-line camelcase
					revision_id: app.form.data( 'revision' ),
					nonce: wpforms_builder.nonce,
					action: 'wpforms_builder_provider_ajax_' + provider,
				};

				$.extend( data, custom );

				return data;
			},

			/**
			 * Make an AJAX request. It's basically a wrapper around jQuery.ajax, but with some defaults.
			 *
			 * @since 1.4.7
			 *
			 * @param {string} provider Current provider slug.
			 * @param {*} custom Object of user-defined $.ajax()-compatible parameters.
			 *
			 * @return {Promise}
			 */
			request: function( provider, custom ) {

				var $holder = app.getProviderHolder( provider ),
					$lock   = $holder.find( '.wpforms-builder-provider-connections-save-lock' ),
					$error  = $holder.find( '.wpforms-builder-provider-connections-error' );

				var params = {
					url: wpforms_builder.ajax_url,
					type: 'post',
					dataType: 'json',
					beforeSend: function() {

						$holder.addClass( 'loading' );
						$lock.val( 1 );
						$error.hide();
					},
				};

				custom.data = app.ajax._mergeData( provider, custom.data || {} );
				$.extend( params, custom );

				return $.ajax( params )
					.fail( function( jqXHR, textStatus, errorThrown ) {

						/*
							* Right now we are logging into browser console.
							* In future that might be something better.
							*/
						console.error( 'provider:', provider );
						console.error( jqXHR );
						console.error( textStatus );

						$lock.val( 1 );
						$error.show();
					} )
					.always( function( dataOrjqXHR, textStatus, jqXHROrerrorThrown ) {

						$holder.removeClass( 'loading' );

						if ( 'success' === textStatus ) {
							$lock.val( 0 );
						}
					} );
			},
		},

		/**
		 * Temporary in-memory cache handling for all providers.
		 *
		 * @since 1.4.7
		 */
		cache: {

			/**
			 * Get the value from cache by key.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @param {string} provider Current provider slug.
			 * @param {string} key Cache key.
			 *
			 * @returns {*} Null if some error occurs.
			 */
			get: function( provider, key ) {

				if (
					typeof __private.cache[ provider ] === 'undefined' ||
					! ( __private.cache[ provider ] instanceof Map )
				) {
					return null;
				}

				return __private.cache[ provider ].get( key );
			},

			/**
			 * Get the value from cache by key and an ID.
			 * Useful when Object is stored under key, and we need specific value.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @param {string} provider Current provider slug.
			 * @param {string} key Cache key.
			 * @param {string} id Cached object ID.
			 *
			 * @returns {*} Null if some error occurs.
			 */
			getById: function( provider, key, id ) {

				if ( typeof this.get( provider, key )[ id ] === 'undefined' ) {
					return null;
				}

				return this.get( provider, key )[ id ];
			},

			/**
			 * Save the data to cache.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @param {string} provider Current provider slug.
			 * @param {string} key Intended to be a string, but can be everything that Map supports as a key.
			 * @param {*} value Data you want to save in cache.
			 *
			 * @returns {Map} All the cache for the provider. IE11 returns 'undefined' for an undefined reason.
			 */
			set: function( provider, key, value ) {

				if (
					typeof __private.cache[ provider ] === 'undefined' ||
					! ( __private.cache[ provider ] instanceof Map )
				) {
					__private.cache[ provider ] = new Map();
				}

				return __private.cache[ provider ].set( key, value );
			},

			/**
			 * Add the data to cache to a particular key.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @example app.cache.as('provider').addTo('connections', connection_id, connection);
			 *
			 * @param {string} provider Current provider slug.
			 * @param {string} key Intended to be a string, but can be everything that Map supports as a key.
			 * @param {string} id ID for a value that should be added to a certain key.
			 * @param {*} value Data you want to save in cache.
			 *
			 * @returns {Map} All the cache for the provider. IE11 returns 'undefined' for an undefined reason.
			 */
			addTo: function( provider, key, id, value ) {

				if (
					typeof __private.cache[ provider ] === 'undefined' ||
					! ( __private.cache[ provider ] instanceof Map )
				) {
					__private.cache[ provider ] = new Map();
					this.set( provider, key, {} );
				}

				var data = this.get( provider, key );
				data[ id ] = value;

				return this.set(
					provider,
					key,
					data
				);
			},

			/**
			 * Delete the cache by key.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @param {string} provider Current provider slug.
			 * @param {string} key Cache key.
			 *
			 * @returns boolean|null True on success, null on data holder failure, false on error.
			 */
			delete: function( provider, key ) {

				if (
					typeof __private.cache[ provider ] === 'undefined' ||
					! ( __private.cache[ provider ] instanceof Map )
				) {
					return null;
				}

				return __private.cache[ provider ].delete( key );
			},

			/**
			 * Delete particular data from a certain key.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @example app.cache.as('provider').deleteFrom('connections', connection_id);
			 *
			 * @param {string} provider Current provider slug.
			 * @param {string} key Intended to be a string, but can be everything that Map supports as a key.
			 * @param {string} id ID for a value that should be deleted from a certain key.
			 *
			 * @returns {Map} All the cache for the provider. IE11 returns 'undefined' for an undefined reason.
			 */
			deleteFrom: function( provider, key, id ) {

				if (
					typeof __private.cache[ provider ] === 'undefined' ||
					! ( __private.cache[ provider ] instanceof Map )
				) {
					return null;
				}

				var data = this.get( provider, key );

				delete data[ id ];

				return this.set(
					provider,
					key,
					data
				);
			},

			/**
			 * Clear all the cache data.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @param {string} provider Current provider slug.
			 */
			clear: function( provider ) {

				if (
					typeof __private.cache[ provider ] === 'undefined' ||
					! ( __private.cache[ provider ] instanceof Map )
				) {
					return;
				}

				__private.cache[ provider ].clear();
			},
		},

		/**
		 * Start the engine. DOM is not ready yet, use only to init something.
		 *
		 * @since 1.4.7
		 */
		init: function() {

			// Do that when DOM is ready.
			$( app.ready );
		},

		/**
		 * DOM is fully loaded.
		 * Should be hooked into in addons, that need to work with DOM, templates etc.
		 *
		 * @since 1.4.7
		 * @since 1.6.1.2 Added initialization for `__private.fields` property.
		 */
		ready: function() {

			// Save a current form fields state.
			__private.fields = $.extend( {}, wpf.getFields( false, true ) );

			app.panelHolder = $( '#wpforms-panel-providers, #wpforms-panel-settings' );

			app.Templates = WPForms.Admin.Builder.Templates;
			app.Templates.add( __private.config.templates );

			app.bindActions();
			app.ui.bindActions();

			app.panelHolder.trigger( 'WPForms.Admin.Builder.Providers.ready' );
		},

		/**
		 * Process all generic actions/events, mostly custom that were fired by our API.
		 *
		 * @since 1.4.7
		 * @since 1.6.1.2 Added a calling `app.updateMapSelects()` method.
		 */
		bindActions: function() {

			// On Form save - notify user about required fields.
			$( document ).on( 'wpformsSaved', function() {

				var $connectionBlocks = app.panelHolder.find( '.wpforms-builder-provider-connection' );

				if ( ! $connectionBlocks.length ) {
					return;
				}

				// We need to show him "Required fields empty" popup only once.
				var isShownOnce = false;

				$connectionBlocks.each( function() {

					var isRequiredEmpty = false;

					// Do the actual required fields check.
					$( this ).find( 'input.wpforms-required, select.wpforms-required, textarea.wpforms-required' ).each( function() {

						const $this = $( this ),
							value = $this.val();

						if ( _.isEmpty( value ) && ! $this.closest( '.wpforms-builder-provider-connection-block' ).hasClass( 'wpforms-hidden' ) ) {
							$( this ).addClass( 'wpforms-error' );
							isRequiredEmpty = true;

							return;
						}

						$( this ).removeClass( 'wpforms-error' );
					} );

					// Notify user.
					if ( isRequiredEmpty && ! isShownOnce ) {
						var $titleArea = $( this ).closest( '.wpforms-builder-provider' ).find( '.wpforms-builder-provider-title' ).clone();
						$titleArea.find( 'button' ).remove();
						var msg = wpforms_builder.provider_required_flds;

						$.alert( {
							title: wpforms_builder.heads_up,
							content: msg.replace( '{provider}', '<strong>' + $titleArea.text().trim() + '</strong>' ),
							icon: 'fa fa-exclamation-circle',
							type: 'orange',
							buttons: {
								confirm: {
									text: wpforms_builder.ok,
									btnClass: 'btn-confirm',
									keys: [ 'enter' ],
								},
							},
						} );

						// Save that we have already showed the user, so we won't bug it anymore.
						isShownOnce = true;
					}
				} );

				// On "Fields" page additional update provider's field mapped items.
				if ( 'fields' === wpf.getQueryString( 'view' ) ) {
					app.updateMapSelects( $connectionBlocks );
				}
			} );

			/*
			 * Update form state when each connection is loaded into the DOM.
			 * This will prevent a please-save-prompt to appear, when navigating
			 * out and back to Marketing tab without doing any changes anywhere.
			 */
			app.panelHolder.on( 'connectionRendered', function() {

				if ( wpf.initialSave === true ) {
					wpf.savedState = wpf.getFormState( '#wpforms-builder-form' );
				}
			} );
		},

		/**
		 * Update selects for mapping if any form fields was added, deleted or changed.
		 *
		 * @since 1.6.1.2
		 *
		 * @param {object} $connections jQuery selector for active connections.
		 */
		updateMapSelects: function( $connections ) {

			var fields = $.extend( {}, wpf.getFields() ),
				currentSaveFields,
				prevSaveFields;

			// We should to detect changes for labels only.
			currentSaveFields = _.mapObject( fields, function( field, key ) {

				return field.label;
			} );
			prevSaveFields    = _.mapObject( __private.fields, function( field, key ) {

				return field.label;
			} );

			// Check if form has any fields and if they have changed labels after previous saving process.
			if (
				( _.isEmpty( currentSaveFields ) && _.isEmpty( prevSaveFields ) ) ||
				( JSON.stringify( currentSaveFields ) === JSON.stringify( prevSaveFields ) )
			) {
				return;
			}

			// Prepare a current form field IDs.
			var fieldIds = Object.keys( currentSaveFields )
				.map( function( id ) {

					return parseInt( id, 10 );
				} );

			// Determine deleted field IDs - it's a diff between previous and current form state.
			var deleted = Object.keys( prevSaveFields )
				.map( function( id ) {

					return parseInt( id, 10 );
				} )
				.filter( function( id ) {

					return ! fieldIds.includes( id );
				} );

			// Remove from mapping selects "deleted" fields.
			for ( var index = 0; index < deleted.length; index++ ) {
				$( '.wpforms-builder-provider-connection-fields-table .wpforms-builder-provider-connection-field-value option[value="' + deleted[ index ] + '"]', $connections ).remove();
			}

			var label, $exists;
			for ( var id in fields ) {

				// Prepare the label.
				if ( typeof fields[ id ].label !== 'undefined' && fields[ id ].label.toString().trim() !== '' ) {
					label = wpf.sanitizeHTML( fields[ id ].label.toString().trim() );
				} else {
					label = wpforms_builder.field + ' #' + id;
				}

				// Try to find all select options by value.
				$exists = $( '.wpforms-builder-provider-connection-fields-table .wpforms-builder-provider-connection-field-value option[value="' + id + '"]', $connections );

				// If no option was found - add a new one for all selects.
				if ( ! $exists.length ) {
					$( '.wpforms-builder-provider-connection-fields-table .wpforms-builder-provider-connection-field-value', $connections ).append( $( '<option>', { value: id, text: label } ) );
					continue;
				}

				// Update a field label if a previous and current labels not equal.
				if ( wpf.sanitizeHTML( fields[ id ].label ) !== wpf.sanitizeHTML( prevSaveFields[ id ] ) ) {
					$exists.text( label );
				}
			}

			// If selects for mapping was changed, that whole form state was changed as well.
			// That's why we need to re-save it.
			if ( wpf.savedState !== wpf.getFormState( '#wpforms-builder-form' ) ) {
				wpf.savedState = wpf.getFormState( '#wpforms-builder-form' );
			}

			// Save form fields state for next saving process.
			__private.fields = fields;

			app.panelHolder.trigger( 'WPForms.Admin.Builder.Providers.updatedMapSelects', [ $connections, fields ] );
		},

		/**
		 * All methods that modify UI of a page.
		 *
		 * @since 1.4.7
		 */
		ui: {

			/**
			 * Process UI related actions/events: click, change etc. - that are triggered from UI.
			 *
			 * @since 1.4.7
			 */
			bindActions: function() {

				// CONNECTION: ADD/DELETE.
				app.panelHolder
					.on( 'click', '.js-wpforms-builder-provider-account-add', function( e ) {

						e.preventDefault();
						app.ui.account.setProvider( $( this ).data( 'provider' ) );
						app.ui.account.add();
					} )
					.on( 'click', '.js-wpforms-builder-provider-connection-add', function( e ) {

						e.preventDefault();
						app.ui.connectionAdd( $( this ).data( 'provider' ) );
					} )
					.on( 'click', '.js-wpforms-builder-provider-connection-delete', function( e ) {

						var $btn = $( this );

						e.preventDefault();
						app.ui.connectionDelete(
							$btn.closest( '.wpforms-builder-provider' ).data( 'provider' ),
							$btn.closest( '.wpforms-builder-provider-connection' )
						);
					} );

				// CONNECTION: FIELDS - ADD/DELETE.
				app.panelHolder
					.on( 'click', '.js-wpforms-builder-provider-connection-fields-add', function( e ) {

						e.preventDefault();

						var $table = $( this ).parents( '.wpforms-builder-provider-connection-fields-table' ),
							$clone = $table.find( 'tr' ).last().clone( true ),
							nextID = parseInt( /\[.+]\[.+]\[.+]\[(\d+)]/.exec( $clone.find( '.wpforms-builder-provider-connection-field-name' ).attr( 'name' ) )[ 1 ], 10 ) + 1;

						// Clear the row and increment the counter.
						$clone.find( '.wpforms-builder-provider-connection-field-name' )
							.attr( 'name', $clone.find( '.wpforms-builder-provider-connection-field-name' ).attr( 'name' ).replace( /\[fields_meta\]\[(\d+)\]/g, '[fields_meta][' + nextID + ']' ) )
							.val( '' );
						$clone.find( '.wpforms-builder-provider-connection-field-value' )
							.attr( 'name', $clone.find( '.wpforms-builder-provider-connection-field-value' ).attr( 'name' ).replace( /\[fields_meta\]\[(\d+)\]/g, '[fields_meta][' + nextID + ']' ) )
							.val( '' );

						// Re-enable "delete" button.
						$clone.find( '.js-wpforms-builder-provider-connection-fields-delete' ).removeClass( 'hidden' );

						// Put it back to the table.
						$table.find( 'tbody' ).append( $clone.get( 0 ) );
					} )
					.on( 'click', '.js-wpforms-builder-provider-connection-fields-delete', function( e ) {

						e.preventDefault();

						var $row = $( this ).parents( '.wpforms-builder-provider-connection-fields-table tr' );

						$row.remove();
					} );

				// CONNECTION: Generated.
				app.panelHolder.on( 'connectionGenerated', function( e, data ) {

					wpf.initTooltips();

					// Hide provider default settings screen.
					$( this )
						.find( '.wpforms-builder-provider-connection[data-connection_id="' + data.connection.id + '"]' )
						.closest( '.wpforms-panel-content-section' )
						.find( '.wpforms-builder-provider-connections-default' )
						.addClass( 'wpforms-hidden' );
				} );

				// CONNECTION: Rendered.
				app.panelHolder.on( 'connectionRendered', function( e, provider, connectionId ) {

					wpf.initTooltips();

					// Some our addons have another arguments for this trigger.
					// We will fix it asap.
					if ( typeof connectionId === 'undefined' ) {
						if ( ! _.isObject( provider ) || ! _.has( provider, 'connection_id' ) ) {
							return;
						}
						connectionId = provider.connection_id;
					}

					// If connection has mapped select fields - call `wpformsFieldUpdate` trigger.
					if ( $( this ).find( '.wpforms-builder-provider-connection[data-connection_id="' + connectionId + '"] .wpforms-field-map-select' ).length ) {
						wpf.fieldUpdate();
					}
				} );

				// Remove error class in required fields if a value is supplied.
				app.panelHolder.on( 'change', '.wpforms-builder-provider select.wpforms-required', function() {

					const $this = $( this );

					if ( ! $this.hasClass( 'wpforms-error' ) || $this.val().length === 0 ) {
						return;
					}

					$this.removeClass( 'wpforms-error' );
				} );
			},

			/**
			 * Add a connection to a page.
			 * This is a multistep process, where the 1st step is always the same for all providers.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @param {string} provider Current provider slug.
			 */
			connectionAdd: function( provider ) {

				$.confirm( {
					title: false,
					content: wpforms_builder_providers.prompt_connection.replace( /%type%/g, 'connection' ) +
						'<input autofocus="" type="text" id="wpforms-builder-provider-connection-name" placeholder="' + wpforms_builder_providers.prompt_placeholder + '">' +
						'<p class="error">' + wpforms_builder_providers.error_name + '</p>',
					icon: 'fa fa-info-circle',
					type: 'blue',
					buttons: {
						confirm: {
							text: wpforms_builder.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {

								var name  = this.$content.find( '#wpforms-builder-provider-connection-name' ).val().trim(),
									error = this.$content.find( '.error' );

								if ( name === '' ) {
									error.show();
									return false;

								} else {
									app.getProviderHolder( provider ).trigger( 'connectionCreate', [ name ] );
								}
							},
						},
						cancel: {
							text: wpforms_builder.cancel,
						},
					},
				} );

			},

			/**
			 * What to do with UI when connection is deleted.
			 *
			 * @since 1.4.7
			 * @since 1.5.9 Added a new parameter - provider.
			 *
			 * @param {string} provider    Current provider slug.
			 * @param {object} $connection jQuery DOM element for a connection.
			 */
			connectionDelete: function( provider, $connection ) {

				$.confirm( {
					title: false,
					content: wpforms_builder_providers.confirm_connection,
					icon: 'fa fa-exclamation-circle',
					type: 'orange',
					buttons: {
						confirm: {
							text: wpforms_builder.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {

								// We need this BEFORE removing, as some handlers might need DOM element.
								app.getProviderHolder( provider ).trigger( 'connectionDelete', [ $connection ] );

								var $section = $connection.closest( '.wpforms-panel-content-section' );

								$connection.fadeOut( 'fast', function() {

									$( this ).remove();

									app.getProviderHolder( provider ).trigger( 'connectionDeleted', [ $connection ] );

									if ( ! $section.find( '.wpforms-builder-provider-connection' ).length ) {
										$section.find( '.wpforms-builder-provider-connections-default' ).removeClass( 'wpforms-hidden' );
									}
								} );
							},
						},
						cancel: {
							text: wpforms_builder.cancel,
						},
					},
				} );
			},

			/**
			 * Account specific methods.
			 *
			 * @since 1.4.8
			 * @since 1.5.8 Added binding `onClose` event.
			 */
			account: {

				/**
				 * Current provider in the context of account creation.
				 *
				 * @since 1.4.8
				 *
				 * @param {string}
				 */
				provider: '',

				/**
				 * Preserve a list of action to perform when new account creation form is submitted.
				 * Provider specific.
				 *
				 * @since 1.4.8
				 *
				 * @param {Array<string, callable>}
				 */
				submitHandlers: [],

				/**
				 * Set the account specific provider.
				 *
				 * @since 1.4.8
				 *
				 * @param {string} provider Provider slug.
				 */
				setProvider: function( provider ) {
					this.provider = provider;
				},

				/**
				 * Add an account for provider.
				 *
				 * @since 1.4.8
				 */
				add: function() {

					var account = this;

					$.confirm( {
						title: false,
						smoothContent: true,
						content: function() {

							var modal = this;

							return app.ajax
								.request( account.provider, {
									data: {
										task: 'account_template_get',
									},
								} )
								.done( function( response ) {

									if ( ! response.success ) {
										return;
									}

									if ( response.data.title.length ) {
										modal.setTitle( response.data.title );
									}

									if ( response.data.content.length ) {
										modal.setContent( response.data.content );
									}

									if ( response.data.type.length ) {
										modal.setType( response.data.type );
									}

									app.getProviderHolder( account.provider ).trigger( 'accountAddModal.content.done', [ modal, account.provider, response ] );
								} )
								.fail( function() {
									app.getProviderHolder( account.provider ).trigger( 'accountAddModal.content.fail', [ modal, account.provider ] );
								} )
								.always( function() {
									app.getProviderHolder( account.provider ).trigger( 'accountAddModal.content.always', [ modal, account.provider ] );
								} );
						},
						contentLoaded: function( data, status, xhr ) {

							var modal = this;

							// Data is already set in content.
							this.buttons.add.enable();
							this.buttons.cancel.enable();

							app.getProviderHolder( account.provider ).trigger( 'accountAddModal.contentLoaded', [ modal ] );
						},
						onOpenBefore: function() { // Before the modal is displayed.

							var modal = this;

							modal.buttons.add.disable();
							modal.buttons.cancel.disable();
							modal.$body.addClass( 'wpforms-providers-account-add-modal' );

							app.getProviderHolder( account.provider ).trigger( 'accountAddModal.onOpenBefore', [ modal ] );
						},
						onClose: function() { // Before the modal is hidden.

							// If an account was configured successfully - show a modal with adding a new connection.
							if ( true === app.ui.account.isConfigured( account.provider ) ) {
								app.ui.connectionAdd( account.provider );
							}
						},
						icon: 'fa fa-info-circle',
						type: 'blue',
						buttons: {
							add: {
								text: wpforms_builder.provider_add_new_acc_btn,
								btnClass: 'btn-confirm',
								keys: [ 'enter' ],
								action: function() {
									var modal = this;

									app.getProviderHolder( account.provider ).trigger( 'accountAddModal.buttons.add.action.before', [ modal ] );

									if (
										! _.isEmpty( account.provider ) &&
										typeof account.submitHandlers[ account.provider ] !== 'undefined'
									) {
										return account.submitHandlers[ account.provider ]( modal );
									}
								},
							},
							cancel: {
								text: wpforms_builder.cancel,
							},
						},
					} );
				},

				/**
				 * Register a template for Add New Account modal window.
				 *
				 * @since 1.4.8
				 */
				registerAddHandler: function( provider, handler ) {

					if ( typeof provider === 'string' && typeof handler === 'function' ) {
						this.submitHandlers[ provider ] = handler;
					}
				},

				/**
				 * Check whether the defined provider is configured or not.
				 *
				 * @since 1.5.8
				 * @since 1.5.9 Added a new parameter - provider.
				 *
				 * @param {string} provider Current provider slug.
				 *
				 * @returns {boolean} Account status.
				 */
				isConfigured: function( provider ) {

					// Check if `Add New Account` button is hidden.
					return app.getProviderHolder( provider ).find( '.js-wpforms-builder-provider-account-add' ).hasClass( 'hidden' );
				},
			},
		},

		/**
		 * Get a jQuery DOM object, that has all the provider-related DOM inside.
		 *
		 * @since 1.4.7
		 *
		 * @returns {object} jQuery DOM element.
		 */
		getProviderHolder: function( provider ) {
			return $( '#' + provider + '-provider' );
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

// Initialize.
WPForms.Admin.Builder.Providers.init();
