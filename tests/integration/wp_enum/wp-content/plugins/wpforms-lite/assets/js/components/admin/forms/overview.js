/* global wpforms_admin, wpforms_forms_locator, wpforms_admin_forms_overview, Choices */
/**
 * WPForms Forms Overview.
 *
 * @since 1.7.3
 */

'use strict';

var WPFormsForms = window.WPFormsForms || {};

WPFormsForms.Overview = WPFormsForms.Overview || ( function( document, window, $ ) {

	/**
	 * Elements.
	 *
	 * @since 1.7.5
	 *
	 * @type {object}
	 */
	var el = {};

	/**
	 * Runtime variables.
	 *
	 * @since 1.7.5
	 *
	 * @type {object}
	 */
	var vars = {};

	/**
	 * Public functions and properties.
	 *
	 * @since 1.7.3
	 *
	 * @type {object}
	 */
	var app = {

		/**
		 * Start the engine.
		 *
		 * @since 1.7.3
		 */
		init: function() {

			$( app.ready );
		},

		/**
		 * Document ready.
		 *
		 * @since 1.7.3
		 */
		ready: function() {

			app.initElements();
			app.initTagsFilter();
			app.adjustBulkEditTagsForm();
			app.initEditTagsBulkActionItem();
			app.events();
		},

		/**
		 * Init elements.
		 *
		 * @since 1.7.5
		 */
		initElements: function() {

			el.$overview            = $( '#wpforms-overview' );
			el.$tagsFilterSelect    = $( '.wpforms-tags-filter select' );
			el.$tagsFilterButton    = $( '.wpforms-tags-filter button' );
			el.$listTableRows       = $( '#wpforms-overview #the-list' );
			el.$bulkEditTagsRows    = $( '.wpforms-bulk-edit-tags' );
			el.$bulkEditTagsForms   = $( '.wpforms-bulk-edit-tags .wpforms-edit-forms select' );
			el.$bulkEditTagsTags    = $( '.wpforms-bulk-edit-tags .wpforms-edit-tags select' );
			el.$bulkEditTagsMessage = $( '.wpforms-bulk-edit-tags .wpforms-message' );
		},

		/**
		 * Register JS events.
		 *
		 * @since 1.7.3
		 */
		events: function() {

			el.$overview
				.on( 'click', '.wp-list-table .delete a, .wp-list-table .duplicate a', app.confirmSingleAction )
				.on( 'click', '.button.delete-all', app.confirmSingleAction )
				.on( 'click', '.bulkactions #doaction', app.confirmBulkAction )
				.on( 'click', '#wpforms-reset-filter .reset', app.resetSearch )
				.on( 'click', '.wp-list-table .wpforms-locations-count, .wp-list-table .row-actions .locations, .wp-list-table .wpforms-locations-close', app.formsLocator )
				.on( 'click', '#the-list .wpforms-column-tags-edit', app.editTagsClick )
				.on( 'click', '#the-list .wpforms-column-tags-edit-cancel', app.cancelEditTagsClick )
				.on( 'click', '#the-list .wpforms-column-tags-edit-save', app.saveEditTagsClick )
				.on( 'click', '#the-list .wpforms-bulk-edit-tags-cancel', app.cancelBulkEditTagsClick )
				.on( 'click', '#the-list .wpforms-bulk-edit-tags-save', app.saveBulkEditTagsClick )
				.on( 'click', '.wpforms-tags-filter .button', app.tagsFilterClick )
				.on( 'click', '.wpforms-manage-tags', app.manageTagsClick )
				.on( 'keydown', '.wpforms-column-tags-form input, .wpforms-bulk-edit-tags input', app.addCustomItemInput )
				.on( 'removeItem', '.choices select', app.editTagsRemoveItem );

			el.$bulkEditTagsForms
				.on( 'removeItem', app.bulkEditTagsFormRemoveItem );

			$( '#adv-settings' )
				.on( 'change', 'input.hide-column-tog', app.adjustBulkEditTagsForm )
				.on( 'change', '#tags-hide', app.toggleTagsColumn );

			$( window )
				.on( 'resize', _.debounce( app.adjustBulkEditTagsForm, 200 ) );

			$( document )
				.on( 'change', '.wpforms-manage-tags-items input', app.manageTagsItemChange );
		},

		/**
		 * Confirm forms deletion and duplications.
		 *
		 * @since 1.7.3
		 *
		 * @param {object} event Event object.
		 */
		confirmSingleAction: function( event ) {

			event.preventDefault();

			var $link = $( this ),
				url = $link.attr( 'href' ),
				msg = $link.hasClass( 'delete-all' ) ?  wpforms_admin.form_delete_all_confirm : '';

			if ( msg === '' ) {
				msg = $link.parent().hasClass( 'delete' ) ? wpforms_admin.form_delete_confirm : wpforms_admin.form_duplicate_confirm;
			}

			app.confirmModal( msg, { 'url': url } );
		},

		/**
		 * Confirm forms bulk deletion.
		 *
		 * @since 1.7.3
		 *
		 * @param {object} event Event object.
		 */
		confirmBulkAction: function( event ) {

			var $button = $( this ),
				$form = $button.closest( 'form' ),
				action = $form.find( '#bulk-action-selector-top' ).val();

			if ( action === 'edit_tags' ) {
				event.preventDefault();
				app.openBulkEditTags();

				return;
			}

			if ( action !== 'delete' ) {
				return;
			}

			event.preventDefault();

			app.confirmModal( wpforms_admin.form_delete_n_confirm, { 'bulk': true, 'form': $form } );
		},

		/**
		 * Open confirmation modal.
		 *
		 * @since 1.7.3
		 *
		 * @param {string} msg  Confirmation modal content.
		 * @param {object} args Additional arguments.
		 */
		confirmModal: function( msg, args ) {

			$.confirm( {
				title: wpforms_admin.heads_up,
				content: msg,
				icon: 'fa fa-exclamation-circle',
				type: 'orange',
				buttons: {
					confirm: {
						text: wpforms_admin.ok,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {

							if ( args.url ) {
								window.location = args.url;

								return;
							}

							if ( args.bulk ) {
								args.form.trigger( 'submit' );
							}
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
		 * Open alert modal.
		 *
		 * @since 1.7.5
		 *
		 * @param {string} msg  Alert modal content.
		 * @param {object} args Additional arguments.
		 */
		alertModal: function( msg, args ) {

			var error = wpforms_admin_forms_overview.strings.error;

			$.confirm( {
				title: args.title || wpforms_admin.oops || false,
				content: msg ? error + '<br>' + msg : error,
				icon: 'fa fa-exclamation-circle',
				type: args.type || 'orange',
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
		 * Reset search form.
		 *
		 * @since 1.7.3
		 *
		 * @param {object} event Event object.
		 */
		resetSearch: function( event ) {

			// Reset search term.
			$( '#wpforms-overview-search-term' ).val( '' );

			// Submit the form.
			$( this ).closest( 'form' ).trigger( 'submit' );
		},

		/**
		 * Show form locations. Take them from Locations column and show in the pane under the form row.
		 *
		 * @since 1.7.4
		 *
		 * @param {object} event Event object.
		 *
		 * @returns {false} Event processing status.
		 */
		formsLocator: function( event ) {

			let $pane = $( '#wpforms-overview-table .wpforms-locations-pane' );

			event.preventDefault();

			const $currentRow = $( event.target.closest( 'tr' ) ),
				$paneRow = $pane.prev().prev(),
				$rowActions = $paneRow.find( '.row-actions' );

			if ( $pane.length > 0 ) {
				$pane.prev().remove();
				$pane.remove();
				$rowActions.removeClass( 'visible' );

				if ( $paneRow.is( $currentRow ) ) {
					return false;
				}
			}

			const $locationsList = $currentRow.find( '.locations-list' );

			if ( $locationsList.length === 0 ) {
				return false;
			}

			const tdNum = $currentRow.find( 'td:not(.hidden)' ).length;
			const locationsHtml = $locationsList.html();
			const html = `<th></th><td colSpan="${tdNum}" class="colspanchange">
				<span class="wpforms-locations-pane-title">${wpforms_forms_locator.paneTitle}</span>
				${locationsHtml}
				<button type="button" class="button wpforms-locations-close alignleft">${wpforms_forms_locator.close}</button>
				</td>`;
			$pane = $( '<tr class="wpforms-locations-pane"></tr>' ).html( html );

			$currentRow.after( $pane );
			$currentRow.after( $( '<tr class="hidden"></tr>' ) );
			$rowActions.addClass( 'visible' );

			return false;
		},

		/**
		 * Click on the Edit link in the "Tags" column.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		editTagsClick: function( event ) {

			var $link = $( this ),
				$td = $link.closest( 'td' ),
				$tbody = $td.closest( 'tbody' ),
				$columnLinks = $td.find( '.wpforms-column-tags-links' ),
				$columnForm = $td.find( '.wpforms-column-tags-form' ),
				$select = $columnForm.find( 'select' );

			event.preventDefault();

			if ( ! $select.length ) {
				$td.append( wpforms_admin_forms_overview.edit_tags_form );
				$columnForm = $td.find( '.wpforms-column-tags-form' );
				$select = $columnForm.find( 'select' );
			}

			// Hide opened tags edit form.
			$tbody.find( '.wpforms-column-tags-links.wpforms-hidden' ).removeClass( 'wpforms-hidden' );
			$tbody.find( '.wpforms-column-tags-form:not(.wpforms-hidden)' ).addClass( 'wpforms-hidden' );

			// Show tags edit form instead of tags links.
			$columnLinks.addClass( 'wpforms-hidden' );
			$columnForm.removeClass( 'wpforms-hidden' );

			// Store current opened Choice.js object and its value.
			vars.currentEditTagsChoicesObj = app.initChoicesJS( $select );
			vars.currentEditTagsValueBackup = vars.currentEditTagsChoicesObj.getValue( true );
		},

		/**
		 * Click on the Cancel button (icon) in Edit Tags form in the "Tags" column.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		cancelEditTagsClick: function( event ) {

			var $btn = $( this ),
				$td = $btn.closest( 'td' ),
				$columnLinks = $td.find( '.wpforms-column-tags-links' ),
				$columnForm = $td.find( '.wpforms-column-tags-form' );

			// Restore saved value from the backup.
			vars.currentEditTagsChoicesObj
				.removeActiveItems()
				.setChoiceByValue( vars.currentEditTagsValueBackup );

			$columnLinks.removeClass( 'wpforms-hidden' );
			$columnForm.addClass( 'wpforms-hidden' );
		},

		/**
		 * Get Tags value.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} choicesObj Choices.js instance.
		 *
		 * @returns {Array} Tags value data.
		 */
		getTagsValue: function( choicesObj ) {

			if ( ! choicesObj || typeof choicesObj.getValue !== 'function' ) {
				return [];
			}

			var tagsValue = choicesObj.getValue(),
				tags = [];

			for ( var i = 0; i < tagsValue.length; i++ ) {
				tags.push( {
					value: tagsValue[ i ].value,
					label: tagsValue[ i ].label,
				} );
			}

			return tags;
		},

		/**
		 * Click on the Save button (icon) in Edit Tags form in the "Tags" column.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		saveEditTagsClick: function( event ) {

			var $btn = $( this ),
				$td = $btn.closest( 'td' ),
				$columnLinks = $td.find( '.wpforms-column-tags-links' ),
				$columnForm = $td.find( '.wpforms-column-tags-form' ),
				$spinner = $btn.siblings( '.wpforms-spinner' ),
				$select = $columnForm.find( 'select' ),
				choicesObj = $select.data( 'choicesjs' );

			// Show spinner.
			$btn.addClass( 'wpforms-hidden' );
			$spinner.removeClass( 'wpforms-hidden' );

			app.saveTagsAjax(
				{
					forms: [ $columnLinks.data( 'form-id' ) ],
					tags:  app.getTagsValue( vars.currentEditTagsChoicesObj ),
				},
				function( res ) {

					// Update tags links in the column.
					$columnLinks.find( '.wpforms-column-tags-links-list' ).html( res.data.tags_links );

					// Update tags ids.
					$columnLinks.data( 'tags', res.data.tags_ids );

					if ( choicesObj ) {
						choicesObj
							.clearStore()
							.setChoices(
								wpforms_admin_forms_overview.all_tags_choices,
								'value',
								'label',
								true
							)
							.setChoiceByValue( res.data.tags_ids.split( ',' ) );
					}
				},
				function() {

					// Hide spinner.
					$btn.removeClass( 'wpforms-hidden' );
					$spinner.addClass( 'wpforms-hidden' );

					// Hide form, show tags links.
					$columnLinks.removeClass( 'wpforms-hidden' );
					$columnForm.addClass( 'wpforms-hidden' );
				}
			);
		},

		/**
		 * Save tags AJAX call routine.
		 *
		 * @since 1.7.5
		 *
		 * @param {object}   data   Post data.
		 * @param {Function} done   Callback on success.
		 * @param {Function} always Always callback.
		 */
		saveTagsAjax: function( data, done, always ) {

			$.post(
				wpforms_admin.ajax_url,
				$.extend(
					{
						action: 'wpforms_admin_forms_overview_save_tags',
						nonce:  wpforms_admin_forms_overview.strings.nonce,
					},
					data
				)
			).done( function( res ) {

				if ( ! res.success || ! res.data ) {
					app.alertModal( res.data || '', {} );

					return;
				}

				app.updateAllTagsChoices( res.data.all_tags_choices );

				if ( typeof done === 'function' ) {
					done( res );
				}

			} ).fail( function( jqXHR, textStatus, errorThrown ) {

				app.alertModal( errorThrown, {} );

			} ).always( function() {

				if ( typeof always === 'function' ) {
					always();
				}
			} );
		},

		/**
		 * Update all tags choices storage.
		 *
		 * @since 1.7.5
		 *
		 * @param {Array} allTagsChoices New all tags choices.
		 */
		updateAllTagsChoices: function( allTagsChoices ) {

			if ( ! allTagsChoices ) {
				return;
			}

			wpforms_admin_forms_overview.all_tags_choices = allTagsChoices;

			// Update Tags Filter items.
			el.$tagsFilterSelect.each( function() {
				app.initChoicesJS( $( this ) );
			} );

			// Show Tags Filter and Manage Tags button if at least one tag exists.
			if ( wpforms_admin_forms_overview.all_tags_choices.length > 0 ) {
				$( '.wpforms-tags-filter, .wpforms-manage-tags' ).removeClass( 'wpforms-hidden' );
			}
		},

		/**
		 * Init Choices.js on the given select input element.
		 *
		 * @since 1.7.5
		 *
		 * @param {jQuery} $select Select input.
		 *
		 * @returns {Choices} Choices.js instance.
		 */
		initChoicesJS: function( $select ) {

			// Skip in certain cases.
			if (
				! wpforms_admin_forms_overview.choicesjs_config ||
				! $select.length ||
				typeof window.Choices !== 'function'
			) {
				return false;
			}

			var choicesObj,
				config = wpforms_admin_forms_overview.choicesjs_config;

			if ( ! $select.data( 'tags-filter' ) ) {
				config.noResultsText = wpforms_admin_forms_overview.strings.add_new_tag;
			}

			// Add arrow placeholder.
			// It is needed to catch the arrow click event in the specific case
			// when Tags Filter has many selected tags which overflow the Choices.js control.
			config.callbackOnInit = function() {
				$select.closest( '.choices__inner' ).append( '<div class="choices__arrow"></div>' );
			};

			// Init or get Choices.js object instance.
			if ( $select.data( 'choice' ) === 'active' ) {
				choicesObj = $select.data( 'choicesjs' );
			} else {
				choicesObj = new Choices( $select[0], config );
			}

			// Backup current value.
			var	currentValue = choicesObj.getValue( true );

			// Update all tags choices. We need to do it evey time, since tags could be added dynamically.
			choicesObj
				.clearStore()
				.setChoices(
					wpforms_admin_forms_overview.all_tags_choices,
					'value',
					'label',
					true
				)
				.setChoiceByValue( currentValue );

			$select.data(
				'choicesjs',
				choicesObj
			);

			return choicesObj;
		},

		/**
		 * Init Edit Tags Bulk Action item.
		 *
		 * @since 1.7.5
		 */
		initEditTagsBulkActionItem: function() {

			if ( wpforms_admin_forms_overview.strings.is_tags_column_hidden ) {
				$( '.bulkactions option[value="edit_tags"]' ).addClass( 'wpforms-hidden' );
			}
		},

		/**
		 * Init tags filter.
		 *
		 * @since 1.7.5
		 */
		initTagsFilter: function() {

			el.$tagsFilterSelect.each( function() {
				app.initChoicesJS( $( this ) );
			} );

			el.$tagsFilterSelect.on( 'change', function() {

				var $choicesObj = el.$tagsFilterSelect.data( 'choicesjs' ),
					$inputText = el.$tagsFilterSelect.siblings( 'input[type="text"]' );

				// Hide placeholder if the Tags Filter is not empty and vice versa.
				if ( $choicesObj.getValue( true ).length > 0 ) {
					$inputText.attr( 'placeholder', '' );
				} else {
					$inputText.attr( 'placeholder', wpforms_admin_forms_overview.strings.all_tags );
				}
			} );
		},

		/**
		 * Click the tags "Filter" button.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		tagsFilterClick: function( event ) {

			var $button = $( this ),
				$select = $button.closest( '.wpforms-tags-filter' ).find( 'select' ),
				choicesObj = $select.data( 'choicesjs' ),
				url = new URL( wpforms_admin_forms_overview.strings.base_url ),
				tagsIds = choicesObj.getValue( true ),
				tags = wpforms_admin_forms_overview.all_tags_choices.filter( function( choice ) {
					return tagsIds.indexOf( choice.value ) > -1;
				} );

			if ( tags.length ) {
				url.searchParams.append(
					'tags',
					_.map( tags, 'slug' ).join( ',' )
				);
			}

			window.location.href = url.href;
		},

		/**
		 * Click the "Manage Tags" button.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		manageTagsClick: function( event ) {

			var options = {
				title: wpforms_admin_forms_overview.strings.manage_tags_title,
				content: app.getManageTagsContent(),
				icon: 'fa fa-tags',
				type: 'blue',
				boxWidth: '550px',
				buttons: {
					cancel: {
						text: wpforms_admin.cancel,
						keys: [ 'esc' ],
					},
				},
				onOpenBefore: function() {

					this.$$confirm && this.$$confirm.prop( 'disabled', true );
					$( 'body' ).addClass( 'wpforms-manage-tags-modal' );
				},
				onDestroy: function() {
					$( 'body' ).removeClass( 'wpforms-manage-tags-modal' );
				},
			};

			var confirm = app.getManageTagsConfirmSettings();

			if ( confirm ) {
				options.buttons = {
					confirm: confirm,
					cancel: options.buttons.cancel,
				};
			}

			$.confirm( options );
		},

		/**
		 * Get Manage Tags modal content.
		 *
		 * @since 1.7.5
		 *
		 * @returns {string} Content of the modal.
		 */
		getManageTagsContent: function() {

			var allTags = wpforms_admin_forms_overview.all_tags_choices;

			if ( allTags.length === 0 ) {
				return wpforms_admin_forms_overview.strings.manage_tags_no_tags;
			}

			var content = wpforms_admin_forms_overview.strings.manage_tags_desc,
				tags = [];

			for ( var i = 0; i < allTags.length; i++ ) {
				tags.push(
					`<input type="checkbox" value="${ allTags[ i ].value }" id="wpforms-tag-${ allTags[ i ].value }">
					<label for="wpforms-tag-${ allTags[ i ].value }">
						${ allTags[ i ].label }
						<span>(${ allTags[ i ].count })</span>
					</label>`
				);
			}

			content += `<div class="wpforms-manage-tags-items">${ tags.join( '' ) }</div>
				<div class="wpforms-manage-tags-notice wpforms-hidden"></div>`;

			return content;
		},

		/**
		 * Get Manage Tags modal confirm button settings.
		 *
		 * @since 1.7.5
		 *
		 * @returns {object} Confirm button settings.
		 */
		getManageTagsConfirmSettings: function() {

			if ( wpforms_admin_forms_overview.all_tags_choices.length === 0 ) {
				return false;
			}

			return {
				text: wpforms_admin_forms_overview.strings.manage_tags_save,
				btnClass: 'btn-confirm',
				keys: [ 'enter' ],
				action: function() {

					var checkedTags = [];

					$( '.wpforms-manage-tags-items input:checked' ).each( function() {
						checkedTags.push( $( this ).val() );
					} );

					$.post(
						wpforms_admin.ajax_url,
						{
							action: 'wpforms_admin_forms_overview_delete_tags',
							nonce:  wpforms_admin_forms_overview.strings.nonce,
							tags: checkedTags,
						}
					).done( function( res ) {

						if ( ! res.success || ! res.data ) {
							app.alertModal( res.data || '', {} );

							return;
						}

						app.manageTagsResultModal( res.data.deleted );

					} ).fail( function( jqXHR, textStatus, errorThrown ) {

						app.alertModal( errorThrown, {} );

					} );
				},
			};
		},

		/**
		 * Change the Tag item hidden checkbox in the Manage Tags modal.
		 *
		 * @since 1.7.5
		 */
		manageTagsItemChange: function() {

			var checkedCount = $( '.wpforms-manage-tags-items input:checked' ).length,
				$saveButton = $( this ).closest( '.jconfirm-box' ).find( '.btn-confirm' ),
				$notice = $( '.wpforms-manage-tags-notice' ),
				noticeHtml = checkedCount > 1 ?
					wpforms_admin_forms_overview.strings.manage_tags_n_tags.replace( '%d', checkedCount ) :
					wpforms_admin_forms_overview.strings.manage_tags_one_tag;

			$saveButton.prop( 'disabled', checkedCount === 0 );

			$notice
				.html( noticeHtml )
				.toggleClass( 'wpforms-hidden', checkedCount === 0 );
		},

		/**
		 * Open modal when the tags were deleted.
		 *
		 * @since 1.7.5
		 *
		 * @param {int} deletedCount Deleted tags count.
		 */
		manageTagsResultModal: function( deletedCount ) {

			var deleted = deletedCount === 1 ?
				wpforms_admin_forms_overview.strings.manage_tags_one_deleted :
				wpforms_admin_forms_overview.strings.manage_tags_n_deleted.replace( '%d', deletedCount );

			$.confirm( {
				title: wpforms_admin_forms_overview.strings.manage_tags_result_title,
				content: `<p>${ deleted }</p><p>${ wpforms_admin_forms_overview.strings.manage_tags_result_text }</p>`,
				icon: 'fa fa-exclamation-circle',
				type: 'green',
				buttons: {
					confirm: {
						text: wpforms_admin_forms_overview.strings.manage_tags_btn_refresh,
						btnClass: 'btn-confirm',
						keys: [ 'enter' ],
						action: function() {
							window.location.href = wpforms_admin_forms_overview.strings.base_url;
						},
					},
				},
			} );
		},

		/**
		 * Bulk edit tags action.
		 *
		 * @since 1.7.5
		 */
		openBulkEditTags: function() {

			var forms = [],
				formsValue = [],
				tagsValue = [];

			// Iterate checked forms.
			el.$listTableRows.find( 'input:checked' ).each( function( i ) {

				var $input = $( this ),
					$tr = $input.closest( 'tr' ),
					$name = $tr.find( '.column-name > a:first-child' ),
					$tags = $tr.find( '.wpforms-column-tags-links' ),
					formTags = $tags.data( 'tags' ).toString() || '';

				if ( $tags.data( 'is-editable' ) !== 1 ) {
					return;
				}

				forms.push( {
					value: $input.val(),
					label: _.escape( $name.text() ),
				} );

				formsValue.push( $input.val() );
				formTags  = formTags.length ? formTags.split( ',' ) : [];
				tagsValue = _.union( tagsValue, formTags );
			} );

			if ( forms.length === 0 ) {
				return;
			}

			el.$bulkEditTagsRows.removeClass( 'wpforms-hidden' );

			// Init Choices.js instance for forms.
			app.initChoicesJS( el.$bulkEditTagsForms )
				.clearStore()
				.setChoices(
					forms,
					'value',
					'label',
					true
				)
				.setChoiceByValue( formsValue );

			// Init Choices.js instance for tags.
			app.initChoicesJS( el.$bulkEditTagsTags )
				.removeActiveItems()
				.setChoiceByValue( tagsValue );

			// Update message.
			app.updateBulkEditTagsFormMessage( formsValue );
		},

		/**
		 * Update the message below the Bulk Edit Tags form.
		 *
		 * @since 1.7.5
		 *
		 * @param {Array} formsValue Forms value.
		 */
		updateBulkEditTagsFormMessage: function( formsValue ) {

			var msg = wpforms_admin_forms_overview.strings.bulk_edit_n_forms;

			if ( formsValue.length === 1 ) {
				msg = wpforms_admin_forms_overview.strings.bulk_edit_one_form;
			}

			el.$bulkEditTagsMessage.html(
				msg.replace( '%d', formsValue.length )
			);
		},

		/**
		 * Remove form from the Bulk Edit Tags form.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		bulkEditTagsFormRemoveItem: function( event ) {

			var formsValue = $( event.target ).data( 'choicesjs' ).getValue( true );

			if ( formsValue.length === 0 ) {
				app.cancelBulkEditTagsClick();
			}

			app.updateBulkEditTagsFormMessage( formsValue );
		},

		/**
		 * Remove tag from Tags editor event handler.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		editTagsRemoveItem: function( event ) {

			var	allValues = _.map( wpforms_admin_forms_overview.all_tags_choices, 'value' );

			if ( allValues.indexOf( event.detail.value ) >= 0 ) {
				return;
			}

			// We should remove new tag from the list of choices.
			var choicesObj = $( event.target ).data( 'choicesjs' ),
				currentValue = choicesObj.getValue( true ),
				choices = _.filter( choicesObj._currentState.choices, function( item ) {
					return item.value !== event.detail.value;
				} );

			choicesObj
				.clearStore()
				.setChoices(
					choices,
					'value',
					'label',
					true
				)
				.setChoiceByValue( currentValue );
		},

		/**
		 * Calculate and set the bulk edit tags form attributes and styles.
		 *
		 * @since 1.7.5
		 */
		adjustBulkEditTagsForm: function() {

			var $columns = $( '.wp-list-table thead .manage-column' ).not( '.hidden' ),
				$formCells = $( '.wpforms-bulk-edit-tags td' ),
				formsWidth = 0;

			// Update colspan attributes.
			$formCells.attr( 'colspan', $columns.length );

			// Generate width property of the forms input element.
			for ( var i = 2; i < $columns.length; i++ ) {
				formsWidth += $columns[ i ].offsetWidth || $columns.eq( i ).outerWidth();
			}

			formsWidth = 'calc( 100% - ' + ( formsWidth - 10 ) + 'px )';

			if ( window.innerWidth < 782 ) {
				formsWidth = 'calc( 100% - 300px )';
			}

			// Update width property of the forms input element.
			el.$bulkEditTagsForms.closest( '.wpforms-edit-forms' ).css( 'width', formsWidth );
		},

		/**
		 * Click toggle Tags column checkbox event handler.
		 *
		 * @since 1.7.5
		 */
		toggleTagsColumn: function() {

			$( '.wpforms-tags-filter, .wpforms-manage-tags, .bulkactions option[value="edit_tags"]' )
				.toggleClass(
					'wpforms-hidden',
					! $( this ).is( ':checked' ) ||
					wpforms_admin_forms_overview.all_tags_choices.length === 0
				);
		},

		/**
		 * Click on the Cancel button in the Bulk Edit Tags form.
		 *
		 * @since 1.7.5
		 */
		cancelBulkEditTagsClick: function() {

			el.$bulkEditTagsRows.addClass( 'wpforms-hidden' );
		},

		/**
		 * Click on the Save button in the Bulk Edit Tags form.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		saveBulkEditTagsClick: function( event ) {

			var $btn = $( this ),
				$spinner = $btn.find( '.wpforms-loading-spinner' ),
				data = {
					forms: el.$bulkEditTagsForms.data( 'choicesjs' ).getValue( true ),
					tags:  app.getTagsValue( el.$bulkEditTagsTags.data( 'choicesjs' ) ),
				};

			// Show spinner.
			$spinner.removeClass( 'wpforms-hidden' );

			app.saveTagsAjax(
				data,
				function( res ) {

					$( '#the-list .tags.column-tags' ).each( function() {

						var $td = $( this ),
							$columnLinks = $td.find( '.wpforms-column-tags-links' ),
							formID = $columnLinks.data( 'form-id' ) + '',
							$select = $td.find( '.wpforms-column-tags-form select' ),
							choicesObj = $select.data( 'choicesjs' );

						if ( data.forms.indexOf( formID ) < 0 ) {
							return;
						}

						// Update tags ids.
						$columnLinks.data( 'tags', res.data.tags_ids );

						// Update tags links in the column.
						$columnLinks.find( '.wpforms-column-tags-links-list' ).html( res.data.tags_links );

						// Update tags options in still not converted selects.
						$select.html( res.data.tags_options );

						if ( choicesObj ) {
							choicesObj
								.clearStore()
								.setChoices(
									wpforms_admin_forms_overview.all_tags_choices,
									'value',
									'label',
									true
								)
								.setChoiceByValue( res.data.tags_ids.split( ',' ) );
						}
					} );

				},
				function() {

					// Hide spinner.
					$spinner.addClass( 'wpforms-hidden' );

					// Hide the form.
					el.$bulkEditTagsRows.addClass( 'wpforms-hidden' );
				}
			);
		},

		/**
		 * Add custom item to Tags dropdown on input.
		 *
		 * @since 1.7.5
		 *
		 * @param {object} event Event object.
		 */
		addCustomItemInput: function( event ) {

			if ( [ 'Enter', ',' ].indexOf( event.key ) < 0 ) {
				return;
			}

			event.preventDefault();
			event.stopPropagation();

			var $select = $( this ).closest( '.choices' ).find( 'select' ),
				choicesObj = $select.data( 'choicesjs' );

			if ( ! choicesObj || event.target.value.length === 0 ) {
				return;
			}

			var	tagLabel = _.escape( event.target.value ).trim(),
				labels = _.map( choicesObj.getValue(), 'label' ).map( function( label ) {
					return label.toLowerCase().trim();
				} );

			if ( tagLabel === '' || labels.indexOf( tagLabel.toLowerCase() ) >= 0 ) {
				choicesObj.clearInput();

				return;
			}

			app.addCustomItemInputTag( choicesObj, tagLabel );
		},

		/**
		 * Add custom item to Tags dropdown on input (second part).
		 *
		 * @since 1.7.5
		 *
		 * @param {object} choicesObj Choices.js instance.
		 * @param {object} tagLabel   Event object.
		 */
		addCustomItemInputTag: function( choicesObj, tagLabel ) {

			var tag = _.find( wpforms_admin_forms_overview.all_tags_choices, { label: tagLabel } );

			if ( tag && tag.value ) {
				choicesObj.setChoiceByValue( tag.value );
			} else {
				choicesObj.setChoices(
					[
						{
							value: tagLabel,
							label: tagLabel,
							selected: true,
						},
					],
					'value',
					'label',
					false
				);
			}

			choicesObj.clearInput();
		},
	};

	// Provide access to public functions/properties.
	return app;

}( document, window, jQuery ) );

WPFormsForms.Overview.init();
