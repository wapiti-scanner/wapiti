var jetpackSearchModule = function () {
	var i,
		j,
		checkboxes,
		filter_list = document.querySelectorAll( '.jetpack-search-filters-widget__filter-list' );

	for ( i = 0; i < filter_list.length; i++ ) {
		filter_list[ i ].addEventListener( 'click', function ( event ) {
			var target = event.target;
			var precedingCheckbox;
			var nextAnchor;

			// If the target is an anchor, we want to toggle the checkbox.
			if ( target.nodeName && 'a' === target.nodeName.toLowerCase() ) {
				precedingCheckbox = target.previousElementSibling;
				if (
					precedingCheckbox &&
					precedingCheckbox.type &&
					'checkbox' === precedingCheckbox.type
				) {
					precedingCheckbox.checked = ! precedingCheckbox.checked;
				}
			}

			// If the target is a checkbox, we want to navigate.
			if ( target.type && 'checkbox' === target.type ) {
				nextAnchor = target.nextElementSibling;
				if ( nextAnchor && 'a' === nextAnchor.nodeName.toLowerCase() ) {
					window.location.href = nextAnchor.getAttribute( 'href' );
				}
			}
		} );

		// Enable checkboxes now that we're setup.
		checkboxes = filter_list[ i ].querySelectorAll( 'input[type="checkbox"]' );
		for ( j = 0; j < checkboxes.length; j++ ) {
			checkboxes[ j ].disabled = false;
			checkboxes[ j ].style.cursor = 'inherit';
		}
	}
};

if ( document.readyState === 'interactive' || document.readyState === 'complete' ) {
	jetpackSearchModule();
} else {
	document.addEventListener( 'DOMContentLoaded', jetpackSearchModule );
}
