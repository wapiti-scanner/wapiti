( function ( $ ) {
	var timeout = null;

	// Make the list of items sortable.
	function initWidget( widget ) {
		widget.find( '.jetpack-social-icons-widget-list' ).sortable( {
			items: '> .jetpack-social-icons-widget-item',
			handle: '.handle',
			cursor: 'move',
			placeholder: 'jetpack-social-icons-widget-item ui-state-placeholder',
			containment: widget,
			forcePlaceholderSize: true,
			update: function () {
				livePreviewUpdate( $( this ).parents( '.form' ).find( '.widget-control-save' ) );
			},
		} );
	}

	// Live preview update.
	function livePreviewUpdate( button ) {
		if ( ! $( document.body ).hasClass( 'wp-customizer' ) || ! button.length ) {
			return;
		}

		button.trigger( 'click' ).hide();
	}

	$( document ).ready( function () {
		// Add an item.
		$( document ).on( 'click', '.jetpack-social-icons-widget.add-button button', function (
			event
		) {
			event.preventDefault();

			var template, widgetContent, widgetList, widgetLastItem, urlId, urlName;

			template = $( $.trim( $( '#tmpl-jetpack-widget-social-icons-template' ).html() ) );
			widgetContent = $( this ).parents( '.widget-content' );
			widgetList = widgetContent.find( '.jetpack-social-icons-widget-list' );
			urlId = widgetList.data( 'url-icon-id' );
			urlName = widgetList.data( 'url-icon-name' );

			template
				.find( '.jetpack-widget-social-icons-url input' )
				.attr( 'id', urlId )
				.attr( 'name', urlName + '[]' );

			widgetList.append( template );

			widgetLastItem = widgetContent.find( '.jetpack-social-icons-widget-item:last' );
			widgetLastItem.find( 'input:first' ).trigger( 'focus' );
		} );

		// Remove an item.
		$( document ).on( 'click', '.jetpack-widget-social-icons-remove-item-button', function (
			event
		) {
			event.preventDefault();
			var widgetItem = $( this ).parents( '.jetpack-social-icons-widget-item' );
			widgetItem.find( 'input' ).change();
			widgetItem.remove();
		} );

		// Event handler for widget open button.
		$( document ).on(
			'click',
			'div.widget[id*="jetpack_widget_social_icons"] .widget-title, div.widget[id*="jetpack_widget_social_icons"] .widget-action',
			function () {
				if ( $( this ).parents( '#available-widgets' ).length ) {
					return;
				}

				initWidget( $( this ).parents( '.widget[id*="jetpack_widget_social_icons"]' ) );
			}
		);

		// Event handler for widget added.
		$( document ).on( 'widget-added', function ( event, widget ) {
			if ( widget.is( '[id*="jetpack_widget_social_icons"]' ) ) {
				event.preventDefault();
				initWidget( widget );
			}
		} );

		// Event handler for widget updated.
		$( document ).on( 'widget-updated', function ( event, widget ) {
			if ( widget.is( '[id*="jetpack_widget_social_icons"]' ) ) {
				event.preventDefault();
				initWidget( widget );
			}
		} );

		// Live preview update on input focus out.
		$( document ).on( 'focusout', 'input[name*="jetpack_widget_social_icons"]', function () {
			livePreviewUpdate( $( this ).parents( '.form' ).find( '.widget-control-save' ) );
		} );

		// Live preview update on input enter key.
		$( document ).on( 'keydown', 'input[name*="jetpack_widget_social_icons"]', function ( event ) {
			if ( event.keyCode === 13 ) {
				livePreviewUpdate( $( this ).parents( '.form' ).find( '.widget-control-save' ) );
			}
		} );

		// Live preview update on input key up 1s.
		$( document ).on( 'keyup', 'input[name*="jetpack_widget_social_icons"]', function () {
			clearTimeout( timeout );

			timeout = setTimeout( function () {
				livePreviewUpdate( $( this ).parents( '.form' ).find( '.widget-control-save' ) );
			}, 1000 );
		} );

		// Live preview update on select change.
		$( document ).on( 'change', 'select[name*="jetpack_widget_social_icons"]', function () {
			livePreviewUpdate( $( this ).parents( '.form' ).find( '.widget-control-save' ) );
		} );
	} );
} )( jQuery );
