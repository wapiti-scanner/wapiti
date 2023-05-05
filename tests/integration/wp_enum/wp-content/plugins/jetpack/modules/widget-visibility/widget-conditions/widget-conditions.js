/* global isRtl, widget_conditions_parent_pages, widget_conditions_data */

jQuery( function ( $ ) {
	//  Gutenberg 'widgets.php' screen.
	var widgets_shell = $( '#widgets-editor' );

	if ( 0 === widgets_shell.length ) {
		// Legacy 'widgets.php' screen + customizer.
		widgets_shell = $( 'div#widgets-right' );

		// For backwards compatibility
		if ( 0 === widgets_shell.length ) {
			widgets_shell = $( 'form#customize-controls' );
		}
	}

	function setWidgetMargin( $widget ) {
		var currentWidth, extra;

		if ( $( 'body' ).hasClass( 'wp-customizer' ) ) {
			// set the inside widget 2 top this way we can see the widget settings
			$widget.find( '.widget-inside' ).css( 'top', 0 );

			return;
		}

		if ( $widget.hasClass( 'expanded' ) ) {
			// The expanded widget must be at least 400px wide in order to
			// contain the visibility settings. IE wasn't handling the
			// margin-left value properly.

			if ( $widget.attr( 'style' ) ) {
				$widget.data( 'original-style', $widget.attr( 'style' ) );
			}

			currentWidth = $widget.width();

			if ( currentWidth < 400 ) {
				extra = 400 - currentWidth;
				if ( isRtl ) {
					$widget
						.css( 'position', 'relative' )
						.css( 'right', '-' + extra + 'px' )
						.css( 'width', '400px' );
				} else {
					$widget
						.css( 'position', 'relative' )
						.css( 'left', '-' + extra + 'px' )
						.css( 'width', '400px' );
				}
			}
		} else if ( $widget.data( 'original-style' ) ) {
			// Restore any original inline styles when visibility is toggled off.
			$widget.attr( 'style', $widget.data( 'original-style' ) ).data( 'original-style', null );
		} else {
			$widget.removeAttr( 'style' );
		}
	}

	function moveWidgetVisibilityButton( $widget ) {
		var $displayOptionsButton = $widget.find( 'a.display-options' ).first(),
			$relativeWidget = $widget.find( 'input.widget-control-save' );

		if ( 0 === $relativeWidget.length ) {
			// The save button doesn't exist in gutenberg widget editor, the conditional HTML ought to be displayed
			// last inside the widget options, so display the button before that.
			$relativeWidget = $widget.find( 'div.widget-conditional' );
		}
		$displayOptionsButton.insertBefore( $relativeWidget );

		// Widgets with no configurable options don't show the Save button's container.
		$displayOptionsButton
			.parent()
			.removeClass( 'widget-control-noform' )
			.find( '.spinner' )
			.remove()
			.css( 'float', 'left' )
			.prependTo( $displayOptionsButton.parent() );
	}

	$( '.widget' ).each( function () {
		moveWidgetVisibilityButton( $( this ) );
	} );

	$( document ).on( 'widget-added', function ( e, $widget ) {
		if ( $widget.find( 'div.widget-control-actions a.display-options' ).length === 0 ) {
			moveWidgetVisibilityButton( $widget );
		}
	} );

	widgets_shell.on( 'click.widgetconditions', 'a.add-condition', function ( e ) {
		var $condition = $( this ).closest( 'div.condition' ),
			$conditionClone = $condition
				.clone()
				.data( 'rule-major', '' )
				.data( 'rule-minor', '' )
				.data( 'has-children', '' )
				.insertAfter( $condition );

		e.preventDefault();

		$conditionClone.find( 'select.conditions-rule-major' ).val( '' );
		$conditionClone.find( 'select.conditions-rule-minor' ).html( '' ).attr( 'disabled' );
		$conditionClone
			.find( 'span.conditions-rule-has-children' )
			.hide()
			.find( 'input[type="checkbox"]' )
			.removeAttr( 'checked' );

		resetRuleIndexes( $conditionClone.closest( '.conditions' ) );
	} );

	widgets_shell.on( 'click.widgetconditions', 'a.display-options', function ( e ) {
		var $displayOptionsButton = $( this ),
			$widget = $displayOptionsButton.closest( 'div.widget' );

		e.preventDefault();

		$widget.find( 'div.widget-conditional' ).toggleClass( 'widget-conditional-hide' );
		$( this ).toggleClass( 'active' );
		$widget.toggleClass( 'expanded' );
		setWidgetMargin( $widget );

		if ( $( this ).hasClass( 'active' ) ) {
			$widget.find( 'input[name=widget-conditions-visible]' ).val( '1' );
			$widget.find( '.condition' ).each( function () {
				buildMinorConditions( $( this ) );
			} );
		} else {
			$widget.find( 'input[name=widget-conditions-visible]' ).val( '0' );
		}
	} );

	widgets_shell.on( 'click.widgetconditions', 'a.delete-condition', function ( e ) {
		var $condition = $( this ).closest( 'div.condition' );

		e.preventDefault();

		if ( $condition.is( ':first-child' ) && $condition.is( ':last-child' ) ) {
			$( this ).closest( 'div.widget' ).find( 'a.display-options' ).click();
			$condition.find( 'select.conditions-rule-major' ).val( '' ).change();
		} else {
			$condition.find( 'select.conditions-rule-major' ).change();
			$condition.detach();
		}

		resetRuleIndexes( $condition.closest( '.conditions' ) );
	} );

	widgets_shell.on( 'click.widgetconditions', 'div.widget-top', function () {
		var $widget = $( this ).closest( 'div.widget' ),
			$displayOptionsButton = $widget.find( 'a.display-options' );

		if ( $displayOptionsButton.hasClass( 'active' ) ) {
			$displayOptionsButton.attr( 'opened', 'true' );
		}

		if ( $displayOptionsButton.attr( 'opened' ) ) {
			$displayOptionsButton.removeAttr( 'opened' );
			$widget.toggleClass( 'expanded' );
			setWidgetMargin( $widget );
		}
	} );

	widgets_shell.on( 'change.widgetconditions', 'input.conditions-match-all', function () {
		$( this )
			.parents( '.widget-conditional' )
			.toggleClass( 'conjunction' )
			.toggleClass( 'intersection' );
	} );

	$( document ).on( 'change.widgetconditions', 'select.conditions-rule-major', function () {
		var $conditionsRuleMajor = $( this ),
			$conditionsRuleMinor = $conditionsRuleMajor.siblings( 'select.conditions-rule-minor:first' ),
			$conditionsRuleHasChildren = $conditionsRuleMajor.siblings(
				'span.conditions-rule-has-children'
			),
			$condition = $conditionsRuleMinor.closest( '.condition' );

		$condition.data( 'rule-minor', '' ).data( 'rule-major', $conditionsRuleMajor.val() );

		if ( $conditionsRuleMajor.val() ) {
			buildMinorConditions( $condition );
		} else {
			$conditionsRuleMajor
				.siblings( 'select.conditions-rule-minor' )
				.attr( 'disabled', 'disabled' )
				.html( '' );
			$conditionsRuleHasChildren.hide().find( 'input[type="checkbox"]' ).removeAttr( 'checked' );
		}
	} );

	$( document ).on( 'change.widgetconditions', 'select.conditions-rule-minor', function () {
		var $conditionsRuleMinor = $( this ),
			$conditionsRuleMajor = $conditionsRuleMinor.siblings( 'select.conditions-rule-major' ),
			$conditionsRuleHasChildren = $conditionsRuleMinor.siblings(
				'span.conditions-rule-has-children'
			),
			$condition = $conditionsRuleMinor.closest( '.condition' );

		$condition.data( 'rule-minor', $conditionsRuleMinor.val() );

		if ( $conditionsRuleMajor.val() === 'page' ) {
			if ( $conditionsRuleMinor.val() in widget_conditions_parent_pages ) {
				$conditionsRuleHasChildren.show();
			} else {
				$conditionsRuleHasChildren.hide().find( 'input[type="checkbox"]' ).removeAttr( 'checked' );
			}
		} else {
			$conditionsRuleHasChildren.hide().find( 'input[type="checkbox"]' ).removeAttr( 'checked' );
		}
	} );

	$( document ).on( 'widget-updated widget-synced', function ( e, widget ) {
		widget.find( '.condition' ).each( function () {
			buildMinorConditions( $( this ) );
		} );
	} );

	function buildMinorConditions( condition ) {
		var minor,
			hasChildren,
			majorData,
			i,
			j,
			key,
			val,
			_len,
			_jlen,
			subkey,
			subval,
			optgroup,
			select = condition.find( '.conditions-rule-minor' ).html( '' ),
			major = condition.data( 'rule-major' );

		// Disable the select, if major rule is empty or if it's a `post_type`.
		// "Post Type" rule has been removed in Jetpack 4.7, and
		// because it breaks all other rules we should `return`.
		if ( ! major || 'post_type' === major ) {
			select.attr( 'disabled', 'disabled' );
			return;
		}

		minor = condition.data( 'rule-minor' );
		hasChildren = condition.data( 'rule-has-children' );
		majorData = widget_conditions_data[ major ];

		for ( i = 0, _len = majorData.length; i < _len; i++ ) {
			key = majorData[ i ][ 0 ];
			val = majorData[ i ][ 1 ];

			if ( typeof val === 'object' ) {
				optgroup = $( '<optgroup/>' ).attr( 'label', key );

				for ( j = 0, _jlen = val.length; j < _jlen; j++ ) {
					subkey = majorData[ i ][ 1 ][ j ][ 0 ];
					subval = majorData[ i ][ 1 ][ j ][ 1 ];

					optgroup.append(
						$( '<option/>' )
							.val( subkey )
							.text( decodeEntities( subval.replace( /&nbsp;/g, '\xA0' ) ) )
					);
				}

				select.append( optgroup );
			} else {
				select.append(
					$( '<option/>' )
						.val( key )
						.text( decodeEntities( val.replace( /&nbsp;/g, '\xA0' ) ) )
				);
			}
		}

		select.removeAttr( 'disabled' );
		select.val( minor );

		if ( 'page' === major && minor in widget_conditions_parent_pages ) {
			select.siblings( 'span.conditions-rule-has-children' ).show();

			if ( hasChildren ) {
				select
					.siblings( 'span.conditions-rule-has-children' )
					.find( 'input[type="checkbox"]' )
					.attr( 'checked', 'checked' );
			}
		} else {
			select
				.siblings( 'span.conditions-rule-has-children' )
				.hide()
				.find( 'input[type="checkbox"]' )
				.removeAttr( 'checked' );
		}
	}

	function resetRuleIndexes( widget ) {
		var index = 0;
		widget
			.find( 'span.conditions-rule-has-children' )
			.find( 'input[type="checkbox"]' )
			.each( function () {
				$( this ).attr( 'name', 'conditions[page_children][' + index + ']' );
				index++;
			} );
	}

	function decodeEntities( encodedString ) {
		var textarea = document.createElement( 'textarea' );
		textarea.innerHTML = encodedString;
		return textarea.value;
	}
} );
