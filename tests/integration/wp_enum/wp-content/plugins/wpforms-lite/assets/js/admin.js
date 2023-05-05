/* global wpforms_admin, jconfirm, wpCookies, Choices, List, wpf */

;( function( $ ) {

	'use strict';

	// Global settings access.
	var s;

	// Admin object.
	var WPFormsAdmin = {

		// Settings.
		settings: {
			iconActivate: '<i class="fa fa-toggle-on fa-flip-horizontal" aria-hidden="true"></i>',
			iconDeactivate: '<i class="fa fa-toggle-on" aria-hidden="true"></i>',
			iconInstall: '<i class="fa fa-cloud-download" aria-hidden="true"></i>',
			iconSpinner: '<i class="fa fa-spinner fa-spin" aria-hidden="true"></i>',
			mediaFrame: false,
		},

		/**
		 * Start the engine.
		 *
		 * @since 1.3.9
		 */
		init: function() {

			// Settings shortcut.
			s = this.settings;

			// Document ready.
			$( WPFormsAdmin.ready );

			// Entries Single (Details).
			WPFormsAdmin.initEntriesSingle();

			// Entries List.
			WPFormsAdmin.initEntriesList();

			// Welcome activation.
			WPFormsAdmin.initWelcome();

			// Addons List.
			$( document ).on( 'wpformsReady', WPFormsAdmin.initAddons );

			// Settings.
			WPFormsAdmin.initSettings();

			// Tools.
			WPFormsAdmin.initTools();

			// Upgrades (Tools view).
			WPFormsAdmin.initUpgrades();
		},

		/**
		 * Document ready.
		 *
		 * @since 1.3.9
		 */
		ready: function() {

			// To prevent jumping (since WP core moves the notices with js),
			// they are hidden initially with CSS, then revealed below with JS,
			// which runs after they have been moved.
			$( '.notice' ).show();

			// If there are screen options we have to move them.
			$( '#screen-meta-links, #screen-meta' ).prependTo( '#wpforms-header-temp' ).show();

			// Init fancy selects via choices.js.
			WPFormsAdmin.initChoicesJS();

			// Init checkbox multi selects columns.
			WPFormsAdmin.initCheckboxMultiselectColumns();

			// Init color pickers via minicolors.js.
			$( '.wpforms-color-picker' ).each( function() {

				const $this = $( this );

				$this.minicolors( {
					defaultValue: $this.data( 'fallback-color' ) || '',
				} );
			} );

			// Init fancy File Uploads.
			$( '.wpforms-file-upload' ).each( function() {
				var $input	 = $( this ).find( 'input[type=file]' ),
					$label	 = $( this ).find( 'label' ),
					labelVal = $label.html();
				$input.on( 'change', function( event ) {
					var fileName = '';
					if ( this.files && this.files.length > 1 ) {
						fileName = ( this.getAttribute( 'data-multiple-caption' ) || '' ).replace( '{count}', this.files.length );
					} else if ( event.target.value ) {
						fileName = event.target.value.split( '\\' ).pop();
					}
					if ( fileName ) {
						$label.find( '.fld' ).html( fileName );
					} else {
						$label.html( labelVal );
					}
				} );

				// Firefox bug fix.
				$input.on( 'focus', function() {
					$input.addClass( 'has-focus' );
				} ).on( 'blur', function() {
					$input.removeClass( 'has-focus' );
				} );
			} );

			// jquery-confirm defaults.
			jconfirm.defaults = {
				closeIcon: false,
				backgroundDismiss: false,
				escapeKey: true,
				animationBounce: 1,
				useBootstrap: false,
				theme: 'modern',
				boxWidth: '400px',
				animateFromElement: false,
				content: wpforms_admin.something_went_wrong,
			};

			// Upgrade information modal for upgrade links.
			$( document ).on( 'click', '.wpforms-upgrade-modal', function() {

				$.alert( {
					title: wpforms_admin.thanks_for_interest,
					content: wpforms_admin.upgrade_modal,
					icon: 'fa fa-info-circle',
					type: 'blue',
					boxWidth: '550px',
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
						},
					},
				} );
			} );

			// Lity lightbox.
			WPFormsAdmin.initLity();

			// Flyout Menu.
			WPFormsAdmin.initFlyoutMenu();

			// Action available for each binding.
			$( document ).trigger( 'wpformsReady' );
		},

		/**
		 * Initialize Choices JS elements.
		 *
		 * @since 1.4.2
		 */
		initChoicesJS: function() {

			$( '.choicesjs-select' ).each( function() {
				var $this = $( this ),
					args  = window.wpforms_admin_choicesjs_config ? { ...window.wpforms_admin_choicesjs_config } : {};

				if ( $this.attr( 'multiple' ) ) {
					args.removeItemButton = typeof args.removeItemButton !== 'undefined' ? args.removeItemButton : true;
				}

				if ( $this.data( 'sorting' ) === 'off' ) {
					args.shouldSort = false;
				}

				if ( $this.data( 'search' ) ) {
					args.searchEnabled = true;
				}

				if ( $this.data( 'choices-position' ) ) {
					args.position = $this.data( 'choices-position' );
				}

				// Function to run once Choices initialises.
				// We need to reproduce a behaviour like on public-facing area for "Edit Entry" page.
				args.callbackOnInit = function() {

					var self      = this,
						$element  = $( self.passedElement.element ),
						sizeClass = $element.data( 'size-class' );

					// Add CSS-class for size.
					if ( sizeClass ) {
						$( self.containerOuter.element ).addClass( sizeClass );
					}

					wpf.initMultipleSelectWithSearch( this );
				};

				$this.data( 'choicesjs', new Choices( $this[0], args ) );
			} );

			// Add ability to close the drop-down menu.
			$( document ).on( 'click', '.choices', function( e ) {

				var $choices =  $( this ),
					choicesObj = $choices.find( 'select' ).data( 'choicesjs' );

				if (
					choicesObj &&
					$choices.hasClass( 'is-open' ) &&
					(
						e.target.classList.contains( 'choices__inner' ) ||
						e.target.classList.contains( 'choices__arrow' )
					)
				) {
					choicesObj.hideDropdown();
				}
			} );
		},

		/**
		 * Initialize checkbox multi-select columns.
		 *
		 * @since 1.4.2
		 */
		initCheckboxMultiselectColumns: function() {

			$( document ).on( 'change', '.checkbox-multiselect-columns input', function() {

				var $this      = $( this ),
					$parent    = $this.parent(),
					$container = $this.closest( '.checkbox-multiselect-columns' ),
					label      = $parent.text(),
					itemID     = 'check-item-' + $this.val(),
					$item      = $container.find( '#' + itemID );

				if ( $this.prop( 'checked' ) ) {
					$this.parent().addClass( 'checked' );
					if ( ! $item.length ) {
						$container.find( '.second-column ul' ).append( '<li id="' + itemID + '">' + label + '</li>' );
					}
				} else {
					$this.parent().removeClass( 'checked' );
					$container.find( '#' + itemID ).remove();
				}
			} );

			$( document ).on( 'click', '.checkbox-multiselect-columns .all', function( event ) {

				event.preventDefault();

				$( this ).closest( '.checkbox-multiselect-columns' ).find( 'input[type=checkbox]' ).prop( 'checked', true ).trigger( 'change' );
				$( this ).remove();
			} );
		},

		//--------------------------------------------------------------------//
		// Forms Overview
		//--------------------------------------------------------------------//

		/**
		 * Element bindings for Form Overview page.
		 *
		 * @since 1.3.9
		 * @since 1.7.3 Deprecated.
		 *
		 * @deprecated Use `WPFormsForms.Overview.init()` instead.
		 */
		initFormOverview: function() {

			console.warn( 'WARNING! Function "WPFormsAdmin.initFormOverview()" has been deprecated, please use the new "WPFormsForms.Overview.init()" function instead!' );

			window.WPFormsForms.Overview.init();
		},

		//--------------------------------------------------------------------//
		// Entry Single (Details)
		//--------------------------------------------------------------------//

		/**
		 * Element bindings for Entries List table page.
		 *
		 * @since 1.3.9
		 */
		initEntriesList: function() {

			$( document ).on( 'click', '#wpforms-entries-table-edit-columns', function( event ) {

				event.preventDefault();

				WPFormsAdmin.entriesListFieldColumn();
			} );

			// Toggle form selector dropdown.
			$( document ).on( 'click', '#wpforms-entries-list .form-selector .toggle', function( event ) {

				event.preventDefault();

				$( this ).toggleClass( 'active' ).next( '.form-list' ).toggle();

			} );

			// Confirm bulk entry deletion.
			$( document ).on( 'click', '#wpforms-entries-table #doaction', function( event ) {

				var $btn     = $( this ),
					$form    = $btn.closest( 'form' ),
					$table   = $form.find( 'table' ),
					$action  = $form.find( 'select[name=action]' ),
					$checked = $table.find( 'input[name^=entry_id]:checked' );

				if ( 'delete' !== $action.val() || ! $checked.length ) {
					return;
				}

				event.preventDefault();

				// Trigger alert modal to confirm.
				$.confirm( {
					title: wpforms_admin.heads_up,
					content: wpforms_admin.entry_delete_n_confirm.replace( '{entry_count}', $checked.length ),
					icon: 'fa fa-exclamation-circle',
					type: 'orange',
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {

								$form.trigger( 'submit' );
							},
						},
						cancel: {
							text: wpforms_admin.cancel,
							keys: [ 'esc' ],
						},
					},
				} );
			} );

			// Confirm entry deletion.
			$( document ).on( 'click', '#wpforms-entries-list .wp-list-table .delete', function( event ) {

				event.preventDefault();

				var url = $( this ).attr( 'href' );

				// Trigger alert modal to confirm.
				$.confirm( {
					title: wpforms_admin.heads_up,
					content: wpforms_admin.entry_delete_confirm,
					icon: 'fa fa-exclamation-circle',
					type: 'orange',
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {
								window.location = url;
							},
						},
						cancel: {
							text: wpforms_admin.cancel,
							keys: [ 'esc' ],
						},
					},
				} );
			} );

			// Toggle entry stars.
			$( document ).on( 'click', '#wpforms-entries-list .wp-list-table .indicator-star', function( event ) {

				event.preventDefault();

				var $this  = $( this ),
					task   = '',
					total  = Number( $( '#wpforms-entries-list .starred-num' ).text() ),
					id     = $this.data( 'id' ),
					formId = $this.data( 'form-id' );

				if ( $this.hasClass( 'star' ) ) {
					task = 'star';
					total++;
					$this.attr( 'title', wpforms_admin.entry_unstar );
				} else {
					task = 'unstar';
					total--;
					$this.attr( 'title', wpforms_admin.entry_star );
				}
				$this.toggleClass( 'star unstar' );
				$( '#wpforms-entries-list .starred-num' ).text( total );

				var data = {
					task    : task,
					action  : 'wpforms_entry_list_star',
					nonce   : wpforms_admin.nonce,
					entryId : id,
					formId  : formId,
				};
				$.post( wpforms_admin.ajax_url, data );
			} );

			// Toggle entry read state.
			$( document ).on( 'click', '#wpforms-entries-list .wp-list-table .indicator-read', function( event ) {

				event.preventDefault();

				var $this = $( this ),
					task  = '',
					total = Number( $( '#wpforms-entries-list .unread-num' ).text() ),
					id    = $this.data( 'id' );

				if ( $this.hasClass( 'read' ) ) {
					task = 'read';
					total--;
					$this.attr( 'title', wpforms_admin.entry_unread );
				} else {
					task = 'unread';
					total++;
					$this.attr( 'title', wpforms_admin.entry_read );
				}
				$this.toggleClass( 'read unread' );
				$( '#wpforms-entries-list .unread-num' ).text( total );

				var data = {
					task    : task,
					action  : 'wpforms_entry_list_read',
					nonce   : wpforms_admin.nonce,
					entryId : id,
					formId  : $this.data( 'form-id' ),
				};
				$.post( wpforms_admin.ajax_url, data );
			} );

			// Confirm mass entry deletion - this deletes ALL entries.
			$( document ).on( 'click', '#wpforms-entries-list .form-details-actions-deleteall', function( event ) {

				event.preventDefault();

				var url           = $( this ).attr( 'href' ),
					$table        = $( '#wpforms-entries-table' ),
					filteredCount = $table.data( 'filtered-count' ) ? parseInt( $table.data( 'filtered-count' ), 10 ) : 0,
					data          = {
						'action': 'wpforms_entry_list_process_delete_all',
						'form_id': $table.find( 'input[name="form_id"]' ).val(),
						'date': $table.find( 'input[name="date"]' ).val(),
						'search': {
							'field': $table.find( 'select[name="search[field]"]' ).val(),
							'comparison': $table.find( 'select[name="search[comparison]"]' ).val(),
							'term': $table.find( 'input[name="search[term]"]' ).val(),
						},
						'nonce': wpforms_admin.nonce,
						'url': url,
					};

				// Trigger alert modal to confirm.
				$.confirm( {
					title: wpforms_admin.heads_up,
					content: filteredCount && $( '#wpforms-reset-filter' ).length ? wpforms_admin.entry_delete_n_confirm.replace( '{entry_count}', filteredCount ) : wpforms_admin.entry_delete_all_confirm,
					icon: 'fa fa-exclamation-circle',
					type: 'orange',
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {

								$.get( wpforms_admin.ajax_url, data )
									.done( function( response ) {

										if ( response.success ) {
											window.location = ! _.isEmpty( response.data ) ? response.data : url;
											return;
										}

										if ( ! _.isEmpty( response.data ) ) {
											console.error( response.data );
										}
									} );
							},
						},
						cancel: {
							text: wpforms_admin.cancel,
							keys: [ 'esc' ],
						},
					},
				} );
			} );

			// Check for new form entries using Heartbeat API.
			$( document ).on( 'heartbeat-send', function( event, data ) {

				var $entriesList = $( '#wpforms-entries-list' );

				// Works on entry list page only.
				if ( ! $entriesList.length || $entriesList.find( '.wpforms-dash-widget' ).length ) {
					return;
				}

				var last_entry_id = $entriesList.find( '#wpforms-entries-table' ).data( 'last-entry-id' );

				// When entries list is filtered, there is no data param at all.
				if ( typeof last_entry_id === 'undefined' ) {
					return;
				}

				data.wpforms_new_entries_entry_id = last_entry_id;
				data.wpforms_new_entries_form_id  = $entriesList.find( 'input[name=form_id]' ).val();
			} );

			// Display entries list notification if Heartbeat API new form entries check is successful.
			$( document ).on( 'heartbeat-tick', function( event, data ) {

				var columnCount;
				var $entriesList = $( '#wpforms-entries-list' );

				// Works on entry list page only.
				if ( ! $entriesList.length ) {
					return;
				}

				if ( ! data.wpforms_new_entries_notification ) {
					return;
				}

				columnCount = $entriesList.find( '.wp-list-table thead tr' ).first().children().length;

				if ( ! $entriesList.find( '.new-entries-notification' ).length ) {
					$entriesList.find( '.wp-list-table thead' )
						.append( '<tr class="new-entries-notification"><td colspan="' + columnCount + '"><a href=""></a></td></tr>' );
				}

				var $link = $entriesList.find( '.new-entries-notification a' );

				$link
					.text( data.wpforms_new_entries_notification )
					.slideDown( {
						start: function() {

							$link.css( 'display', 'block' );
						},
						always: function() {

							$link.css( 'display', 'block' );
						},
					} );
			} );
		},

		/**
		 * Element bindings for Entries Single (Details) page.
		 *
		 * @since 1.3.9
		 */
		initEntriesSingle: function() {

			// Entry navigation hotkeys.
			// We only want to listen on the applicable admin page.
			if ( 'wpforms-entries' === WPFormsAdmin.getQueryString( 'page' ) && 'details' === WPFormsAdmin.getQueryString( 'view' ) ) {
				WPFormsAdmin.entryHotkeys();
			}

			// Confirm entry deletion.
			$( document ).on( 'click', '#wpforms-entries-single .submitdelete', function( event ) {

				event.preventDefault();

				var url = $( this ).attr( 'href' );

				// Trigger alert modal to confirm.
				$.confirm( {
					title: wpforms_admin.heads_up,
					content: wpforms_admin.entry_delete_confirm,
					icon: 'fa fa-exclamation-circle',
					type: 'orange',
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {
								window.location = url;
							},
						},
						cancel: {
							text: wpforms_admin.cancel,
							keys: [ 'esc' ],
						},
					},
				} );
			} );

			// Open Print preview in new window.
			$( document ).on( 'click', '#wpforms-entries-single .wpforms-entry-print a', function( event ) {

				event.preventDefault();

				window.open( $( this ).attr( 'href' ) );
			} );

			// Toggle displaying empty fields.
			$( document ).on( 'click', '#wpforms-entries-single .wpforms-empty-field-toggle', function( event ) {

				event.preventDefault();

				// Handle cookie.
				if ( wpCookies.get( 'wpforms_entry_hide_empty' ) === 'true' ) {

					// User was hiding empty fields, so now display them.
					wpCookies.remove( 'wpforms_entry_hide_empty' );
					$( this ).text( wpforms_admin.entry_empty_fields_hide );
				} else {

					// User was seeing empty fields, so now hide them.
					wpCookies.set( 'wpforms_entry_hide_empty', 'true', 2592000 ); // 1month.
					$( this ).text( wpforms_admin.entry_empty_fields_show );
				}

				$( '.wpforms-entry-field.empty, .wpforms-edit-entry-field.empty' ).toggle();
			} );

			// Display notes editor.
			$( document ).on( 'click', '#wpforms-entries-single .wpforms-entry-notes-new .add', function( event ) {

				event.preventDefault();

				$( this ).hide().next( 'form' ).stop().slideToggle();
			} );

			// Cancel note.
			$( document ).on( 'click', '#wpforms-entries-single .wpforms-entry-notes-new .cancel', function( event ) {

				event.preventDefault();

				$( this ).closest( 'form' ).stop().slideToggle();
				$( '.wpforms-entry-notes-new .add' ).show();
			} );

			// Delete note.
			$( document ).on( 'click', '#wpforms-entries-single .wpforms-entry-notes-byline .note-delete', function( event ) {

				event.preventDefault();

				var url = $( this ).attr( 'href' );

				// Trigger alert modal to confirm.
				$.confirm( {
					title: wpforms_admin.heads_up,
					content: wpforms_admin.entry_note_delete_confirm,
					icon: 'fa fa-exclamation-circle',
					type: 'orange',
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
							action: function() {
								window.location = url;
							},
						},
						cancel: {
							text: wpforms_admin.cancel,
							keys: [ 'esc' ],
						},
					},
				} );
			} );
		},


		//--------------------------------------------------------------------//
		// Entry List
		//--------------------------------------------------------------------//

		/**
		 * Hotkeys for Entries Single (Details) page.
		 *
		 * j triggers previous entry, k triggers next entry.
		 *
		 * @since 1.4.0
		 */
		entryHotkeys: function() {

			// eslint-disable-next-line complexity
			$( document ).on( 'keydown', function( event ) {
				if ( 74 === event.keyCode && ! WPFormsAdmin.isFormTypeNode( event.target.nodeName ) ) {

					// j key has been pressed outside a form element, go to the previous entry.
					var prevEntry = $( '#wpforms-entry-prev-link' ).attr( 'href' );
					if ( '#' !== prevEntry ) {
						window.location.href = prevEntry;
					}
				} else if ( 75 === event.keyCode && ! WPFormsAdmin.isFormTypeNode( event.target.nodeName ) ) {

					// k key has been pressed outside a form element, go to the previous entry.
					var nextEntry = $( '#wpforms-entry-next-link' ).attr( 'href' );
					if ( '#' !== nextEntry ) {
						window.location.href = nextEntry;
					}
				}
			} );
		},

		/**
		 * Display settings to change the entry list field columns/
		 *
		 * @since 1.4.0
		 */
		entriesListFieldColumn: function() {

			$.alert( {
				title: wpforms_admin.entry_field_columns,
				boxWidth: '500px',
				content: s.iconSpinner + $( '#wpforms-field-column-select' ).html(),
				onContentReady: function() {

					var $modalContent = this.$content,
						$select       = $modalContent.find( 'select' ),
						choices       = new Choices( $select[0], {
							shouldSort: false,
							removeItemButton: true,
							loadingText: wpforms_admin.choicesjs_loading,
							noResultsText: wpforms_admin.choicesjs_no_results,
							noChoicesText: wpforms_admin.choicesjs_no_choices,
							itemSelectText: wpforms_admin.choicesjs_item_select,
							fuseOptions: window.wpforms_admin_choicesjs_config.fuseOptions,
							callbackOnInit: function() {
								$modalContent.find( '.fa' ).remove();
								$modalContent.find( 'form' ).show();
							},
						} );

					$( '.jconfirm-content-pane, .jconfirm-box' ).css( 'overflow', 'visible' );

					choices.passedElement.element.addEventListener( 'change', function() {

						// Without `true` parameter dropdown will be hidden together with modal window when `Enter` is pressed.
						choices.hideDropdown( true );
					}, false );
				},
				buttons: {
					confirm: {
						text: wpforms_admin.save_refresh,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {
							this.$content.find( 'form' ).trigger( 'submit' );
						},
					},
					cancel: {
						text: wpforms_admin.cancel,
						keys: [ 'esc' ],
					},
				},
			} );
		},

		//--------------------------------------------------------------------//
		// Welcome Activation.
		//--------------------------------------------------------------------//

		/**
		 * Welcome activation page.
		 *
		 * @since 1.3.9
		 */
		initWelcome: function() {

			// Open modal and play How To video.
			$( document ).on( 'click', '#wpforms-welcome .play-video', function( event ) {

				event.preventDefault();

				var video = '<div class="video-container"><iframe width="1280" height="720" src="https://www.youtube-nocookie.com/embed/o2nE1P74WxQ?rel=0&amp;showinfo=0&amp;autoplay=1" frameborder="0" allowfullscreen></iframe></div>';

				$.dialog( {
					title: false,
					content: video,
					closeIcon: true,
					boxWidth: '70%',
				} );
			} );
		},

		//--------------------------------------------------------------------//
		// Addons List.
		//--------------------------------------------------------------------//

		/**
		 * Element bindings for Addons List page.
		 *
		 * @since 1.3.9
		 */
		initAddons: function() {

			// Only run on the addons page.
			if ( ! $( '#wpforms-admin-addons' ).length ) {
				return;
			}

			// Addons searching.
			if ( $( '#wpforms-admin-addons-list' ).length ) {
				var addonSearch = new List(
					'wpforms-admin-addons-list',
					{
						valueNames: [ 'addon-link' ],
					}
				);

				$( '#wpforms-admin-addons-search' ).on(
					'keyup search',
					function() {
						WPFormsAdmin.updateAddonSearchResult( this, addonSearch );
					}
				);
			}

			// Toggle an addon state.
			$( document ).on( 'click', '#wpforms-admin-addons .addon-item button', function( event ) {

				event.preventDefault();

				if ( $( this ).hasClass( 'disabled' ) ) {
					return false;
				}

				WPFormsAdmin.addonToggle( $( this ) );
			} );
		},

		/**
		 * Handle addons search field operations.
		 *
		 * @since 1.7.4
		 *
		 * @param {object} searchField The search field html element.
		 * @param {object} addonSearch Addons list (uses List.js).
		 */
		updateAddonSearchResult: function( searchField, addonSearch ) {

			var searchTerm = $( searchField ).val(),
				$heading   = $( '#addons-heading' );

			if ( searchTerm ) {
				$heading.text( wpforms_admin.addon_search );
			} else {
				$heading.text( $heading.data( 'text' ) );
			}

			/*
			 * Replace dot and comma with space
			 * it is workaround for a bug in listjs library.
			 *
			 * Note: remove when the issue below is fixed:
			 * @see https://github.com/javve/list.js/issues/699
			 */
			searchTerm = searchTerm.replace( /[.,]/g, ' ' );

			addonSearch.search( searchTerm );
		},

		/**
		 * Change plugin/addon state.
		 *
		 * @since 1.6.3
		 *
		 * @param {string}   plugin     Plugin slug or URL for download.
		 * @param {string}   state      State status activate|deactivate|install.
		 * @param {string}   pluginType Plugin type addon or plugin.
		 * @param {Function} callback   Callback for get result from AJAX.
		 */
		setAddonState: function( plugin, state, pluginType, callback ) {

			var actions = {
					'activate': 'wpforms_activate_addon',
					'install': 'wpforms_install_addon',
					'deactivate': 'wpforms_deactivate_addon',
				},
				action = actions[ state ];

			if ( ! action ) {
				return;
			}

			var data = {
				action: action,
				nonce: wpforms_admin.nonce,
				plugin: plugin,
				type: pluginType,
			};

			$.post( wpforms_admin.ajax_url, data, function( res ) {

				callback( res );
			} ).fail( function( xhr ) {

				console.log( xhr.responseText );
			} );
		},

		/**
		 * Toggle addon state.
		 *
		 * @since 1.3.9
		 */
		addonToggle: function( $btn ) {

			var $addon = $btn.closest( '.addon-item' ),
				plugin = $btn.attr( 'data-plugin' ),
				pluginType = $btn.attr( 'data-type' ),
				state,
				cssClass,
				stateText,
				buttonText,
				errorText,
				successText;

			if ( $btn.hasClass( 'status-go-to-url' ) ) {

				// Open url in new tab.
				window.open( $btn.attr( 'data-plugin' ), '_blank' );
				return;
			}

			$btn.prop( 'disabled', true ).addClass( 'loading' );
			$btn.html( s.iconSpinner );

			if ( $btn.hasClass( 'status-active' ) ) {

				// Deactivate.
				state = 'deactivate';
				cssClass = 'status-installed';
				if ( pluginType === 'plugin' ) {
					cssClass += ' button button-secondary';
				}
				stateText = wpforms_admin.addon_inactive;
				buttonText = wpforms_admin.addon_activate;
				errorText  = wpforms_admin.addon_deactivate;
				if ( pluginType === 'addon' ) {
					buttonText = s.iconActivate + buttonText;
					errorText  = s.iconDeactivate + errorText;
				}

			} else if ( $btn.hasClass( 'status-installed' ) ) {

				// Activate.
				state = 'activate';
				cssClass = 'status-active';
				if ( pluginType === 'plugin' ) {
					cssClass += ' button button-secondary disabled';
				}
				stateText = wpforms_admin.addon_active;
				buttonText = wpforms_admin.addon_deactivate;
				if ( pluginType === 'addon' ) {
					buttonText = s.iconDeactivate + buttonText;
					errorText  = s.iconActivate + wpforms_admin.addon_activate;
				} else if ( pluginType === 'plugin' ) {
					buttonText = wpforms_admin.addon_activated;
					errorText  = wpforms_admin.addon_activate;
				}

			} else if ( $btn.hasClass( 'status-missing' ) ) {

				// Install & Activate.
				state = 'install';
				cssClass = 'status-active';
				if ( pluginType === 'plugin' ) {
					cssClass += ' button disabled';
				}
				stateText = wpforms_admin.addon_active;
				buttonText = wpforms_admin.addon_activated;
				errorText  = s.iconInstall;
				if ( pluginType === 'addon' ) {
					buttonText = s.iconActivate + wpforms_admin.addon_deactivate;
					errorText += wpforms_admin.addon_install;
				}

			} else {
				return;
			}
			// eslint-disable-next-line complexity
			WPFormsAdmin.setAddonState( plugin, state, pluginType, function( res ) {

				if ( res.success ) {
					if ( 'install' === state ) {
						$btn.attr( 'data-plugin', res.data.basename );
						successText = res.data.msg;
						if ( ! res.data.is_activated ) {
							stateText  = wpforms_admin.addon_inactive;
							buttonText = 'plugin' === pluginType ? wpforms_admin.addon_activate : s.iconActivate + wpforms_admin.addon_activate;
							cssClass   = 'plugin' === pluginType ? 'status-installed button button-secondary' : 'status-installed';
						}
					} else {
						successText = res.data;
					}
					$addon.find( '.actions' ).append( '<div class="msg success">' + successText + '</div>' );
					$addon.find( 'span.status-label' )
						.removeClass( 'status-active status-installed status-missing' )
						.addClass( cssClass )
						.removeClass( 'button button-primary button-secondary disabled' )
						.text( stateText );
					$btn
						.removeClass( 'status-active status-installed status-missing' )
						.removeClass( 'button button-primary button-secondary disabled' )
						.addClass( cssClass ).html( buttonText );
				} else {
					if ( 'object' === typeof res.data ) {
						if ( pluginType === 'addon' ) {
							$addon.find( '.actions' ).append( '<div class="msg error"><p>' + wpforms_admin.addon_error + '</p></div>' );
						} else {
							$addon.find( '.actions' ).append( '<div class="msg error"><p>' + wpforms_admin.plugin_error + '</p></div>' );
						}
					} else {
						$addon.find( '.actions' ).append( '<div class="msg error"><p>' + res.data + '</p></div>' );
					}
					if ( 'install' === state && 'plugin' === pluginType ) {
						$btn.addClass( 'status-go-to-url' ).removeClass( 'status-missing' );
					}
					$btn.html( errorText );
				}

				$btn.prop( 'disabled', false ).removeClass( 'loading' );

				if ( ! $addon.find( '.actions' ).find( '.msg.error' ).length ) {
					setTimeout( function() {

						$( '.addon-item .msg' ).remove();
					}, 3000 );
				}
			} );
		},

		//--------------------------------------------------------------------//
		// Settings.
		//--------------------------------------------------------------------//

		/**
		 * Element bindings for Settings page.
		 *
		 * @since 1.3.9
		 */
		initSettings: function() {

			// On ready events.
			$( document ).on( 'wpformsReady', function() {

				// Only proceed if we're on the settings page.
				if ( ! $( '#wpforms-settings' ).length ) {
					return;
				}

				// Watch for hashes and scroll to if found.
				// Display all addon boxes as the same height.
				var integrationFocus = WPFormsAdmin.getQueryString( 'wpforms-integration' ),
					jumpTo           = WPFormsAdmin.getQueryString( 'jump' );

				if ( integrationFocus ) {
					$( 'body' ).animate(
						{ scrollTop: $( '#wpforms-integration-' + integrationFocus ).offset().top },
						1000
					);
				} else if ( jumpTo ) {
					$( 'body' ).animate(
						{ scrollTop: $( '#' + jumpTo ).offset().top },
						1000
					);
				}

				// Settings conditional logic.
				$( '.wpforms-admin-settings-form' ).conditions( [

					// Misc > Disable User Cookies visibility.
					{
						conditions: {
							element:  '#wpforms-setting-gdpr',
							type:     'checked',
							operator: 'is',
						},
						actions: {
							if: {
								element: '#wpforms-setting-row-gdpr-disable-uuid,#wpforms-setting-row-gdpr-disable-details',
								action:	 'show',
							},
							else : {
								element: '#wpforms-setting-row-gdpr-disable-uuid,#wpforms-setting-row-gdpr-disable-details',
								action:	 'hide',
							},
						},
						effect: 'appear',
					},

					// CAPTCHA > Type.
					{
						conditions: {
							element:   'input[name=captcha-provider]:checked',
							type:      'value',
							operator:  '=',
							condition: 'hcaptcha',
						},
						actions: {
							if: [
								{
									element: '.wpforms-setting-row',
									action: 'show',
								},
								{
									element: '.wpforms-setting-recaptcha, #wpforms-setting-row-captcha-provider .desc, #wpforms-setting-row-recaptcha-site-key, #wpforms-setting-row-recaptcha-secret-key, #wpforms-setting-row-recaptcha-fail-msg, .wpforms-setting-turnstile, #wpforms-setting-row-captcha-provider .desc, #wpforms-setting-row-turnstile-heading, #wpforms-setting-row-turnstile-site-key, #wpforms-setting-row-turnstile-secret-key, #wpforms-setting-row-turnstile-theme, #wpforms-setting-row-turnstile-fail-msg',
									action: 'hide',
								},
							],
						},
						effect: 'appear',
					},
					{
						conditions: {
							element:   'input[name=captcha-provider]:checked',
							type:      'value',
							operator:  '=',
							condition: 'recaptcha',
						},
						actions: {
							if: [
								{
									element: '.wpforms-setting-row',
									action: 'show',
								},
								{
									element: '#wpforms-setting-row-captcha-provider .desc, #wpforms-setting-row-hcaptcha-heading, #wpforms-setting-row-hcaptcha-site-key, #wpforms-setting-row-hcaptcha-secret-key, #wpforms-setting-row-hcaptcha-fail-msg, #wpforms-setting-row-captcha-provider .desc, #wpforms-setting-row-turnstile-heading, #wpforms-setting-row-turnstile-site-key, #wpforms-setting-row-turnstile-secret-key, #wpforms-setting-row-turnstile-theme, #wpforms-setting-row-turnstile-fail-msg',
									action: 'hide',
								},
							],
						},
						effect: 'appear',
					},
					{
						conditions: {
							element:   'input[name=captcha-provider]:checked',
							type:      'value',
							operator:  '=',
							condition: 'turnstile',
						},
						actions: {
							if: [
								{
									element: '.wpforms-setting-row',
									action: 'show',
								},
								{
									element: '#wpforms-setting-row-captcha-provider .desc, #wpforms-setting-row-hcaptcha-heading, #wpforms-setting-row-hcaptcha-site-key, #wpforms-setting-row-hcaptcha-secret-key, #wpforms-setting-row-hcaptcha-fail-msg, .wpforms-setting-recaptcha, #wpforms-setting-row-captcha-provider .desc, #wpforms-setting-row-recaptcha-site-key, #wpforms-setting-row-recaptcha-secret-key, #wpforms-setting-row-recaptcha-fail-msg',
									action: 'hide',
								},
							],
						},
						effect: 'appear',
					},
					{
						conditions: {
							element:   'input[name=captcha-provider]:checked',
							type:      'value',
							operator:  '=',
							condition: 'none',
						},
						actions: {
							if: [
								{
									element: '.wpforms-setting-row',
									action: 'hide',
								},
								{
									element: '.wpforms-setting-captcha-heading, #wpforms-setting-row-captcha-provider, #wpforms-setting-row-captcha-provider .desc',
									action: 'show',
								},
							],
						},
						effect: 'appear',
					},
				] );
			} );

			// Render engine setting.
			$( document ).on( 'change', '#wpforms-setting-row-render-engine input', WPFormsAdmin.settingsRenderEngineChange );

			// Form styles plugin setting.
			$( document ).on( 'change', '#wpforms-setting-disable-css', function() {

				WPFormsAdmin.settingsFormStylesAlert( $( this ).val() );
			} );

			// Image upload fields.
			$( document ).on( 'click', '.wpforms-setting-row-image button', function( event ) {

				event.preventDefault();

				WPFormsAdmin.imageUploadModal( $( this ) );
			} );

			// Verify license key.
			$( document ).on( 'click', '#wpforms-setting-license-key-verify', function( event ) {

				event.preventDefault();

				WPFormsAdmin.licenseVerify( $( this ) );
			} );

			// Show message for license field.
			$( document ).on( 'click', '.wpforms-setting-license-wrapper', function( event ) {

				event.preventDefault();

				var $keyField = $( '#wpforms-setting-license-key' );

				if ( ! $keyField.length ) {
					return;
				}

				if ( ! $keyField.prop( 'disabled' ) ) {
					return;
				}

				WPFormsAdmin.licenseEditMessage();
			} );

			// Deactivate license key.
			$( document ).on( 'click', '#wpforms-setting-license-key-deactivate', function( event ) {

				event.preventDefault();

				WPFormsAdmin.licenseDeactivate( $( this ) );
			} );

			// Refresh license key.
			$( document ).on( 'click', '#wpforms-setting-license-key-refresh', function( event ) {

				event.preventDefault();

				WPFormsAdmin.licenseRefresh( $( this ) );
			} );

			/**
			 * @todo Refactor providers settings tab. Code below is legacy.
			 */

			// Integration connect.
			$( document ).on( 'click', '.wpforms-settings-provider-connect', function( event ) {

				event.preventDefault();

				var button = $( this );

				WPFormsAdmin.integrationConnect( button );
			} );

			// Integration account disconnect.
			$( document ).on( 'click', '.wpforms-settings-provider-accounts-list .remove a', function( event ) {

				event.preventDefault();

				WPFormsAdmin.integrationDisconnect( $( this ) );
			} );

			// Integration individual display toggling.
			$( document ).on( 'click', '.wpforms-settings-provider:not(.focus-out) .wpforms-settings-provider-header', function( event ) {

				event.preventDefault();

				var $this = $( this );

				$this
					.parent()
					.find( '.wpforms-settings-provider-accounts' )
					.stop()
					.slideToggle( '', function() {
						$this.parent().find( '.wpforms-settings-provider-logo i' ).toggleClass( 'fa-chevron-right fa-chevron-down' );
					} );
			} );

			// Integration accounts display toggling.
			$( document ).on( 'click', '.wpforms-settings-provider-accounts-toggle a', function( event ) {

				event.preventDefault();

				var $connectFields = $( this ).parent().next( '.wpforms-settings-provider-accounts-connect' );
				$connectFields.find( 'input[type=text], input[type=password]' ).val( '' );
				$connectFields.stop().slideToggle();
			} );

			// CAPTCHA settings page: type toggling.
			$( document ).on( 'change', '#wpforms-setting-row-captcha-provider input', function() {

				var $preview = $( '#wpforms-setting-row-captcha-preview' );

				if ( this.value === 'hcaptcha' || this.value === 'turnstile' ) {
					$preview.removeClass( 'wpforms-hidden' );
				} else if ( this.value === 'none' ) {
					$preview.addClass( 'wpforms-hidden' );
				} else {
					$( '#wpforms-setting-row-recaptcha-type input:checked' ).trigger( 'change' );
				}

				if ( $preview.find( '.wpforms-captcha-preview' ).length ) {
					$preview.find( '.wpforms-captcha-preview' ).empty();
					$preview.find( '.wpforms-captcha-placeholder' ).removeClass( 'wpforms-hidden' );
				}
			} );

			// CAPTCHA settings page: reCAPTCHA type toggling.
			$( document ).on( 'change', '#wpforms-setting-row-recaptcha-type input', function() {

				$( '#wpforms-setting-row-captcha-preview' ).toggleClass( 'wpforms-hidden', 'v2' !== this.value );
				$( '#wpforms-setting-row-recaptcha-v3-threshold' ).toggleClass( 'wpforms-hidden', 'v3' !== this.value );
			} );

			// Toggle control switch description.
			$( document ).on( 'change', '.wpforms-toggle-control input', function() {

				var $input = $( this ),
					checked = $input.is( ':checked' ),
					$field = $input.closest( '.wpforms-setting-field' ),
					$descOn = $field.find( '.wpforms-toggle-desc.desc-on' ),
					$descOff = $field.find( '.wpforms-toggle-desc.desc-off' ),
					isDoubleDesc = $descOn.length > 0 && $descOff.length > 0;

				$descOn.toggleClass( 'wpforms-hidden', ! checked && isDoubleDesc );
				$descOff.toggleClass( 'wpforms-hidden', checked && isDoubleDesc );
			} );
		},

		/**
		 * Render engine setting change event handler.
		 *
		 * @since 1.8.1
		 *
		 * @param {object} e Event object.
		 */
		settingsRenderEngineChange: function( e ) {

			// noinspection JSUnusedLocalSymbols
			// eslint-disable-next-line
			const renderEngine = $( this ).val();

			// TODO: Add corresponding code that need to be executed on change render engine setting.
		},

		/**
		 * Alert users if they change form styles to something that may give
		 * unexpected results.
		 *
		 * @since 1.5.0
		 */
		settingsFormStylesAlert: function( value ) {

			if ( '2' === value ) {
				var msg = wpforms_admin.settings_form_style_base;
			} else if ( '3' === value ) {
				var msg = wpforms_admin.settings_form_style_none;
			} else {
				return;
			}

			$.alert( {
				title: wpforms_admin.heads_up,
				content: msg,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_admin.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
					},
				},
			} );
		},

		/**
		 * Image upload modal window.
		 *
		 * @since 1.3.0
		 */
		imageUploadModal: function( el ) {

			if ( s.media_frame ) {
				s.media_frame.open();
				return;
			}

			var $setting = $( el ).closest( '.wpforms-setting-field' );

			s.media_frame = wp.media.frames.wpforms_media_frame = wp.media( {
				className: 'media-frame wpforms-media-frame',
				frame: 'select',
				multiple: false,
				title: wpforms_admin.upload_image_title,
				library: {
					type: 'image',
				},
				button: {
					text: wpforms_admin.upload_image_button,
				},
			} );

			s.media_frame.on( 'select', function() {

				// Grab our attachment selection and construct a JSON representation of the model.
				var media_attachment = s.media_frame.state().get( 'selection' ).first().toJSON();

				// Send the attachment URL to our custom input field via jQuery.
				$setting.find( 'input[type=text]' ).val( media_attachment.url );
				$setting.find( 'img' ).remove();
				$setting.prepend( '<img src="' + media_attachment.url + '">' );
			} );

			// Now that everything has been set, let's open up the frame.
			s.media_frame.open();
		},

		/**
		 * Verify a license key.
		 *
		 * @since 1.3.9
		 *
		 * @param {jQuery} $el Verify button element.
		 */
		licenseVerify: function( $el ) {

			var $row        = $el.closest( '.wpforms-setting-row' ),
				$keyField   = $( '#wpforms-setting-license-key' ),
				buttonWidth = $el.outerWidth(),
				buttonLabel = $el.text(),
				data        = {
					action: 'wpforms_verify_license',
					nonce:   wpforms_admin.nonce,
					license: $keyField.val(),
				};

			$el.html( s.iconSpinner ).css( 'width', buttonWidth ).prop( 'disabled', true );

			$.post( wpforms_admin.ajax_url, data, function( res ) {

				var icon  = 'fa fa-check-circle',
					color = 'green',
					msg;

				if ( res.success ) {
					msg = res.data.msg;
					$el.hide();
					$row.find( '#wpforms-setting-license-key-info-message' ).empty().hide();
					$row.find( '.type, .desc, #wpforms-setting-license-key-deactivate' ).show();
					$row.find( '.type strong' ).text( res.data.type );
					$( '.wpforms-license-notice' ).remove();
					$keyField
						.prop( 'disabled', true )
						.addClass( 'wpforms-setting-license-is-valid' )
						.attr( 'value', $keyField.val() );
				} else {
					icon  = 'fa fa-exclamation-circle';
					color = 'orange';
					msg   = res.data;
					$row.find( '.type, .desc, #wpforms-setting-license-key-deactivate' ).hide();
					$keyField.prop( 'disabled', false );
				}

				$.alert( {
					title: false,
					content: msg,
					icon: icon,
					type: color,
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
						},
					},
				} );

				$el.html( buttonLabel ).css( 'width', 'auto' ).prop( 'disabled', false );

			} ).fail( function( xhr ) {
				$keyField.prop( 'disabled', false );
				console.log( xhr.responseText );
			} );
		},

		/**
		 * Show message that license key editing is disabled.
		 *
		 * @since 1.6.5
		 */
		licenseEditMessage: function() {

			$.alert( {
				title: wpforms_admin.heads_up,
				content: wpforms_admin.edit_license,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_admin.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
					},
				},
			} );
		},

		/**
		 * Deactivate a license key.
		 *
		 * @since 1.3.9
		 *
		 * @param {Element} el Button element.
		 */
		licenseDeactivate: function( el ) {

			const $this = $( el );
			const $row  = $this.closest( '.wpforms-setting-row' );

			const buttonWidth = $this.outerWidth();
			const buttonLabel = $this.text();

			const data = {
				action: 'wpforms_deactivate_license',
				nonce: wpforms_admin.nonce,
			};

			$this.html( s.iconSpinner ).css( 'width', buttonWidth ).prop( 'disabled', true );

			$.post( wpforms_admin.ajax_url, data, function( res ) {

				let icon  = 'fa fa-info-circle';
				let color = 'blue';
				let title = wpforms_admin.success;

				const data = res.data;
				const msg  = ! data.msg || typeof data.msg !== 'string' ? wpforms_admin.something_went_wrong : data.msg;

				if ( res.success ) {
					$row.find( '#wpforms-setting-license-key' )
						.val( '' )
						.attr( 'value', '' )
						.prop( { readonly: false, disabled: false } )
						.removeClass();
					$row.find( '.wpforms-license-key-deactivate-remove' ).remove();
					$row.find( '#wpforms-setting-license-key-info-message' ).html( data.info ).show();
					$row.find( '#wpforms-setting-license-key-verify' ).prop( 'disabled', false ).show();
					$row.find( '.type, .desc, #wpforms-setting-license-key-deactivate' ).hide();
				} else {
					icon  = 'fa fa-exclamation-circle';
					color = 'orange';
					title = wpforms_admin.oops;
				}

				$.alert( {
					title: title,
					content: msg,
					icon: icon,
					type: color,
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
						},
					},
				} );

				$this.html( buttonLabel ).css( 'width', 'auto' ).prop( 'disabled', false );

			} ).fail( function( xhr ) {
				console.log( xhr.responseText );
			} );
		},

		/**
		 * Refresh a license key.
		 *
		 * @since 1.3.9
		 */
		licenseRefresh: function( el ) {

			var $this       = $( el ),
				$row        = $this.closest( '.wpforms-setting-row' ),
				$input      = $( '#wpforms-setting-license-key' ),
				data        = {
					action: 'wpforms_refresh_license',
					nonce:   wpforms_admin.nonce,
					license: $input.val(),
				};

			$.post( wpforms_admin.ajax_url, data, function( res ) {

				var icon  = 'fa fa-check-circle',
					color = 'green',
					msg;

				if ( res.success ) {
					msg = res.data.msg;
					$row.find( '.type strong' ).text( res.data.type );
				} else {
					icon  = 'fa fa-exclamation-circle';
					color = 'orange';
					msg   = res.data;
					$row.find( '.type, .desc' ).hide();
					$input.removeClass( 'wpforms-setting-license-is-valid' ).addClass( 'wpforms-setting-license-is-invalid' );
				}

				$.alert( {
					title: false,
					content: msg,
					icon: icon,
					type: color,
					buttons: {
						confirm: {
							text: wpforms_admin.ok,
							btnClass: 'btn-confirm',
							keys: [ 'enter' ],
						},
					},
				} );

			} ).fail( function( xhr ) {
				console.log( xhr.responseText );
			} );
		},

		/**
		 * Connect integration provider account.
		 *
		 * @param $btn Button (.wpforms-settings-provider-connect) that was clicked to establish connection.
		 *
		 * @since 1.3.9
		 */
		integrationConnect: function( $btn ) {

			var buttonWidth = $btn.outerWidth(),
				buttonLabel = $btn.text(),
				$provider   = $btn.closest( '.wpforms-settings-provider' ),
				data        = {
					action  : 'wpforms_settings_provider_add_' + $btn.data( 'provider' ),
					data    : $btn.closest( 'form' ).serialize(),
					provider: $btn.data( 'provider' ),
					nonce   : wpforms_admin.nonce,
				},
				errorMessage = wpforms_admin.provider_auth_error;

			$btn.html( wpforms_admin.connecting ).css( 'width', buttonWidth ).prop( 'disabled', true );

			$.post( wpforms_admin.ajax_url, data, function( response ) {

				if ( response.success ) {
					$provider.find( '.wpforms-settings-provider-accounts-list ul' ).append( response.data.html );
					$provider.addClass( 'connected' );
					$btn.closest( '.wpforms-settings-provider-accounts-connect' ).stop().slideToggle();

				} else {

					if (
						Object.prototype.hasOwnProperty.call( response, 'data' ) &&
						Object.prototype.hasOwnProperty.call( response.data, 'error_msg' )
					) {
						errorMessage += '<br>' + response.data.error_msg;
					}

					WPFormsAdmin.integrationError( errorMessage );
				}

			} ).fail( function() {

				WPFormsAdmin.integrationError( errorMessage );
			} ).always( function() {

				$btn.html( buttonLabel ).css( 'width', 'auto' ).prop( 'disabled', false );
			} );
		},

		/**
		 * Remove integration provider account.
		 *
		 * @since 1.3.9
		 *
		 * @param {object} el Disconnect link that was clicked to establish removing account.
		 */
		integrationDisconnect: function( el ) {

			var $this     = $( el ),
				$provider = $this.parents( '.wpforms-settings-provider' ),
				data      = {
					action  : 'wpforms_settings_provider_disconnect_' + $this.data( 'provider' ),
					provider: $this.data( 'provider' ),
					key     : $this.data( 'key' ),
					nonce   : wpforms_admin.nonce,
				},
				errorMessage = wpforms_admin.provider_delete_error;

			$.confirm( {
				title: wpforms_admin.heads_up,
				content: wpforms_admin.provider_delete_confirm,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_admin.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							$.post( wpforms_admin.ajax_url, data, function( response ) {

								if ( response.success ) {
									$this.parent().parent().remove();

									// Hide Connected status label if no more integrations are linked.
									var numberOfIntegrations = $provider.find( '.wpforms-settings-provider-accounts-list li' ).length;

									if ( typeof numberOfIntegrations === 'undefined' || numberOfIntegrations === 0 ) {
										$provider.removeClass( 'connected' );
									}

									/**
									 * Provider account has been removed.
									 *
									 * @since 1.7.7
									 */
									$( document ).trigger( 'wpformsProviderRemoved', [ $provider, response ] );
								} else {

									if (
										Object.prototype.hasOwnProperty.call( response, 'data' ) &&
										Object.prototype.hasOwnProperty.call( response.data, 'error_msg' )
									) {
										errorMessage += '<br>' + response.data.error_msg;
									}

									WPFormsAdmin.integrationError( errorMessage );
								}
							} ).fail( function() {

								WPFormsAdmin.integrationError( errorMessage );
							} );
						},
					},
					cancel: {
						text: wpforms_admin.cancel,
						keys: [ 'esc' ],
					},
				},
			} );
		},

		/**
		 * Error handling.
		 *
		 * @since 1.6.4
		 *
		 * @param {string} error Error message.
		 */
		integrationError: function( error ) {

			$.alert( {
				title: wpforms_admin.something_went_wrong,
				content: error,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_admin.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
					},
				},
			} );
		},

		//--------------------------------------------------------------------//
		// Tools.
		//--------------------------------------------------------------------//

		/**
		 * Element bindings for Tools page.
		 *
		 * @since 1.4.2
		 */
		initTools: function() {

			// Run import for a specific provider.
			$( document ).on( 'click', '#wpforms-ssl-verify', function( event ) {

				event.preventDefault();

				WPFormsAdmin.verifySSLConnection();
			} );

			// Run import for a specific provider.
			$( document ).on( 'click', '#wpforms-importer-forms-submit', function( event ) {

				event.preventDefault();

				// Check to confirm user as selected a form.
				if ( $( '#wpforms-importer-forms input:checked' ).length ) {

					var ids = [];
					$( '#wpforms-importer-forms input:checked' ).each( function( i ) {
						ids[i] = $( this ).val();
					} );

					if ( ! wpforms_admin.isPro ) {

						// We need to analyze the forms before starting the actual import.
						WPFormsAdmin.analyzeForms( ids );
					} else {

						// Begin the import process.
						WPFormsAdmin.importForms( ids );
					}

				} else {

					// User didn't actually select a form so alert them.
					$.alert( {
						title: wpforms_admin.heads_up,
						content: wpforms_admin.importer_forms_required,
						icon: 'fa fa-info-circle',
						type: 'blue',
						buttons: {
							confirm: {
								text: wpforms_admin.ok,
								btnClass: 'btn-confirm',
								keys: [ 'enter' ],
							},
						},
					} );
				}
			} );

			// Continue import after analyzing.
			$( document ).on( 'click', '#wpforms-importer-continue-submit', function( event ) {

				event.preventDefault();

				WPFormsAdmin.importForms( s.formIDs );
			} );
		},

		/**
		 * Perform test connection to verify that the current web host
		 * can successfully make outbound SSL connections.
		 *
		 * @since 1.4.5
		 */
		verifySSLConnection: function() {

			var $btn      = $( '#wpforms-ssl-verify' ),
				btnLabel  = $btn.text(),
				btnWidth  = $btn.outerWidth(),
				$settings = $btn.parent(),
				data      = {
					action: 'wpforms_verify_ssl',
					nonce:   wpforms_admin.nonce,
				};

			$btn.css( 'width', btnWidth ).prop( 'disabled', true ).text( wpforms_admin.testing );

			// Trigger AJAX to test connection
			$.post( wpforms_admin.ajax_url, data, function( res ) {

				console.log( res );

				// Remove any previous alerts.
				$settings.find( '.wpforms-alert, .wpforms-ssl-error' ).remove();

				if ( res.success ) {
					$btn.before( '<div class="wpforms-alert wpforms-alert-success">' + res.data.msg + '</div>' );
				}

				if ( ! res.success && res.data.msg ) {
					$btn.before( '<div class="wpforms-alert wpforms-alert-danger">' + res.data.msg + '</div>' );
				}

				if ( ! res.success && res.data.debug ) {
					$btn.before( '<div class="wpforms-ssl-error pre-error">' + res.data.debug + '</div>' );
				}

				$btn.css( 'width', btnWidth ).prop( 'disabled', false ).text( btnLabel );
			} );
		},

		/**
		 * Begins the process of analyzing the forms.
		 *
		 * This runs for non-Pro installs to check if any of the forms to be
		 * imported contain fields
		 * not currently available.
		 *
		 * @since 1.4.2
		 */
		analyzeForms: function( forms ) {

			var $processAnalyze = $( '#wpforms-importer-analyze' );

			// Display total number of forms we have to import.
			$processAnalyze.find( '.form-total' ).text( forms.length );
			$processAnalyze.find( '.form-current' ).text( '1' );

			// Hide the form select section.
			$( '#wpforms-importer-forms' ).hide();

			// Show Analyze status.
			$processAnalyze.show();

			// Create global analyze queue.
			s.analyzeQueue   = forms;
			s.analyzed       = 0;
			s.analyzeUpgrade = [];
			s.formIDs        = forms;

			// Analyze the first form in the queue.
			WPFormsAdmin.analyzeForm();
		},

		/**
		 * Analyze a single form from the queue.
		 *
		 * @since 1.4.2
		 */
		analyzeForm: function() {

			var $analyzeSettings = $( '#wpforms-importer-analyze' ),
				formID           = _.first( s.analyzeQueue ),
				provider         = WPFormsAdmin.getQueryString( 'provider' ),
				data             = {
					action:  'wpforms_import_form_' + provider,
					analyze: 1,
					form_id: formID,
					nonce:   wpforms_admin.nonce,
				};

			// Trigger AJAX analyze for this form.
			$.post( wpforms_admin.ajax_url, data, function( res ) {

				if ( res.success ) {

					if ( ! _.isEmpty( res.data.upgrade_plain ) || ! _.isEmpty( res.data.upgrade_omit ) ) {
						s.analyzeUpgrade.push( {
							name:   res.data.name,
							fields: _.union( res.data.upgrade_omit, res.data.upgrade_plain ),
						} );
					}

					// Remove this form ID from the queue.
					s.analyzeQueue = _.without( s.analyzeQueue, formID );
					s.analyzed++;

					if ( _.isEmpty( s.analyzeQueue ) ) {

						if ( _.isEmpty( s.analyzeUpgrade ) ) {

							// Continue to import forms as no Pro fields were found.
							WPFormsAdmin.importForms( s.formIDs );
						} else {

							// We found Pro fields, so alert the user.
							var upgradeDetails = wp.template( 'wpforms-importer-upgrade' );
							$analyzeSettings.find( '.upgrade' ).append( upgradeDetails( s.analyzeUpgrade ) );
							$analyzeSettings.find( '.upgrade' ).show();
							$analyzeSettings.find( '.process-analyze' ).hide();
						}

					} else {

						// Analyze next form in the queue.
						$analyzeSettings.find( '.form-current' ).text( s.analyzed + 1 );
						WPFormsAdmin.analyzeForm();
					}
				}
			} );
		},

		/**
		 * Begins the process of importing the forms.
		 *
		 * @since 1.4.2
		 */
		importForms: function( forms ) {

			var $processSettings = $( '#wpforms-importer-process' );

			// Display total number of forms we have to import.
			$processSettings.find( '.form-total' ).text( forms.length );
			$processSettings.find( '.form-current' ).text( '1' );

			// Hide the form select and form analyze sections.
			$( '#wpforms-importer-forms, #wpforms-importer-analyze' ).hide();

			// Show processing status.
			$processSettings.show();

			// Create global import queue.
			s.importQueue = forms;
			s.imported    = 0;

			// Import the first form in the queue.
			WPFormsAdmin.importForm();
		},

		/**
		 * Imports a single form from the import queue.
		 *
		 * @since 1.4.2
		 */
		importForm: function() {

			var $processSettings = $( '#wpforms-importer-process' ),
				formID           = _.first( s.importQueue ),
				provider         = WPFormsAdmin.getQueryString( 'provider' ),
				data             = {
					action:  'wpforms_import_form_' + provider,
					form_id: formID,
					nonce:   wpforms_admin.nonce,
				};

			// Trigger AJAX import for this form.
			$.post( wpforms_admin.ajax_url, data, function( res ) {

				if ( res.success ) {
					var statusUpdate;

					if ( res.data.error ) {
						statusUpdate = wp.template( 'wpforms-importer-status-error' );
					} else {
						statusUpdate = wp.template( 'wpforms-importer-status-update' );
					}

					$processSettings.find( '.status' ).prepend( statusUpdate( res.data ) );
					$processSettings.find( '.status' ).show();

					// Remove this form ID from the queue.
					s.importQueue = _.without( s.importQueue, formID );
					s.imported++;

					if ( _.isEmpty( s.importQueue ) ) {

						$processSettings.find( '.process-count' ).hide();
						$processSettings.find( '.forms-completed' ).text( s.imported );
						$processSettings.find( '.process-completed' ).show();

					} else {

						// Import next form in the queue.
						$processSettings.find( '.form-current' ).text( s.imported + 1 );
						WPFormsAdmin.importForm();

					}
				}
			} );
		},

		//--------------------------------------------------------------------//
		// Upgrades (Tabs view).
		//--------------------------------------------------------------------//

		/**
		 * Element bindings for Tools page.
		 *
		 * @since 1.4.3
		 */
		initUpgrades: function() {

			// Prepare to run the v1.4.3 upgrade routine.
			$( document ).on( 'click', '#wpforms-upgrade-143 button', function( event ) {

				event.preventDefault();

				var $this       = $( this ),
					buttonWidth = $this.outerWidth(),
					$status     = $( '#wpforms-upgrade-143 .status' ),
					data        = {
						action:    'wpforms_upgrade_143',
						nonce:      wpforms_admin.nonce,
						init:       true,
						incomplete: $this.data( 'incomplete' ),
					};

				// Change the button to indicate we are doing initial processing.
				$this.html( s.iconSpinner ).css( 'width', buttonWidth ).prop( 'disabled', true );

				// Get the total number of entries, then kick off the routine.
				$.post( wpforms_admin.ajax_url, data, function( res ) {
					if ( res.success ) {

						// Set initial values.
						s.upgraded     = Number( res.data.upgraded );
						s.upgradeTotal = Number( res.data.total );
						var percent    = Math.round( ( Number( s.upgraded ) / Number( s.upgradeTotal ) ) * 100 );

						// Show the status area.
						$this.remove();
						$status.find( '.bar' ).css( 'width', percent + '%' );
						$status.show().find( '.total' ).text( s.upgradeTotal );
						$status.find( '.current' ).text( s.upgraded );
						$status.find( '.percent' ).text( percent + '%' );

						// Begin the actual upgrade routine.
						WPFormsAdmin.upgrade143();
					}
				} );
			} );
		},

		/**
		 * The v1.4.3 entry fields upgrade routine.
		 *
		 * @since 1.4.3
		 */
		upgrade143: function() {

			var $status     = $( '#wpforms-upgrade-143 .status' ),
				data        = {
					action:   'wpforms_upgrade_143',
					nonce:    wpforms_admin.nonce,
					upgraded: s.upgraded,
				};

			// Get the total number of entries, then kick off the routine.
			$.post( wpforms_admin.ajax_url, data, function( res ) {
				if ( res.success ) {

					s.upgraded  = Number( s.upgraded ) + Number( res.data.count );
					var percent = Math.round( ( Number( s.upgraded ) / Number( s.upgradeTotal ) ) * 100 );

					// Update progress bar.
					$status.find( '.bar' ).css( 'width',  percent + '%' );

					if ( Number( res.data.count ) < 10 ) {

						// This batch completed the upgrade routine.
						$status.find( '.progress-bar' ).addClass( 'complete' );
						$status.find( '.msg' ).text( wpforms_admin.upgrade_completed );
					} else {

						$status.find( '.current' ).text( s.upgraded );
						$status.find( '.percent' ).text( percent + '%' );

						// Batch the next round of entries.
						WPFormsAdmin.upgrade143();
					}
				}
			} );
		},

		/**
		 * Element bindings for Flyout Menu.
		 *
		 * @since 1.5.7
		 */
		initFlyoutMenu: function() {

			// Flyout Menu Elements.
			var $flyoutMenu    = $( '#wpforms-flyout' );

			if ( $flyoutMenu.length === 0 ) {
				return;
			}

			var	$head   = $flyoutMenu.find( '.wpforms-flyout-head' ),
				$sullie = $head.find( 'img' ),
				menu    = {
					state: 'inactive',
					srcInactive: $sullie.attr( 'src' ),
					srcActive: $sullie.data( 'active' ),
				};

			// Click on the menu head icon.
			$head.on( 'click', function( e ) {

				e.preventDefault();

				if ( menu.state === 'active' ) {
					$flyoutMenu.removeClass( 'opened' );
					$sullie.attr( 'src', menu.srcInactive );
					menu.state = 'inactive';
				} else {
					$flyoutMenu.addClass( 'opened' );
					$sullie.attr( 'src', menu.srcActive );
					menu.state = 'active';
				}
			} );

			// Page elements and other values.
			var $wpfooter = $( '#wpfooter' );

			if ( $wpfooter.length === 0 ) {
				return;
			}

			var	$overlap = $(
				'#wpforms-overview, ' +
				'#wpforms-entries-list, ' +
				'#wpforms-tools.wpforms-tools-tab-action-scheduler, ' +
				'#wpforms-tools.wpforms-tools-tab-logs'
			);

			// Hide menu if scrolled down to the bottom of the page.
			$( window ).on( 'resize scroll', _.debounce( function( e ) {

				var wpfooterTop    = $wpfooter.offset().top,
					wpfooterBottom = wpfooterTop + $wpfooter.height(),
					overlapBottom  = $overlap.length > 0 ? $overlap.offset().top + $overlap.height() + 85 : 0,
					viewTop        = $( window ).scrollTop(),
					viewBottom     = viewTop + $( window ).height();

				if ( wpfooterBottom <= viewBottom && wpfooterTop >= viewTop && overlapBottom > viewBottom ) {
					$flyoutMenu.addClass( 'out' );
				} else {
					$flyoutMenu.removeClass( 'out' );
				}
			}, 50 ) );

			$( window ).trigger( 'scroll' );
		},

		/**
		 * Lity improvements.
		 *
		 * @since 1.5.8
		 */
		initLity: function() {

			// Use `data-lity-srcset` opener's attribute for add srcset to full image in opened lightbox.
			$( document ).on( 'lity:ready', function( event, instance ) {

				var $el     = instance.element(),
					$opener = instance.opener(),
					srcset = typeof $opener !== 'undefined' ? $opener.data( 'lity-srcset' ) : '';

				if ( typeof srcset !== 'undefined' && srcset !== '' ) {
					$el.find( '.lity-content img' ).attr( 'srcset', srcset );
				}
			} );
		},

		//--------------------------------------------------------------------//
		// Helper functions.
		//--------------------------------------------------------------------//

		/**
		 * Return if the target nodeName is a form element.
		 *
		 * @since 1.4.0
		 */
		isFormTypeNode: function( name ) {

			name = name || false;

			if ( 'TEXTAREA' === name || 'INPUT' === name || 'SELECT' === name ) {
				return true;
			}

			return false;
		},

		/**
		 * Get query string in a URL.
		 *
		 * @since 1.3.9
		 */
		getQueryString: function( name ) {

			var match = new RegExp( '[?&]' + name + '=([^&]*)' ).exec( window.location.search );
			return match && decodeURIComponent( match[1].replace( /\+/g, ' ' ) );
		},

		/**
		 * Debug output helper.
		 *
		 * @since 1.4.4
		 * @param msg
		 */
		debug: function( msg ) {

			if ( WPFormsAdmin.isDebug() ) {
				if ( typeof msg === 'object' || msg.constructor === Array ) {
					console.log( 'WPForms Debug:' );
					console.log( msg );
				} else {
					console.log( 'WPForms Debug: ' + msg );
				}
			}
		},

		/**
		 * Is debug mode.
		 *
		 * @since 1.4.4
		 */
		isDebug: function() {

			return ( window.location.hash && '#wpformsdebug' === window.location.hash );
		},
	};

	WPFormsAdmin.init();

	window.WPFormsAdmin = WPFormsAdmin;

} )( jQuery );
