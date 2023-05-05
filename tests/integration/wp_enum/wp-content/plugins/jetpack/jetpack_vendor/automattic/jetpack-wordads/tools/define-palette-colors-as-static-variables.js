const webpack = require( 'webpack' );

// TODO: Migrate this to a common package in the monorepo to avoid code duplication.

/**
 * Returns an instance of the DefinePlugin that adds color-studio colors as literals.
 *
 * @returns {object} DefinePlugin instance.
 */
function definePaletteColorsAsStaticVariables() {
	return new webpack.DefinePlugin( {
		// Replace palette colors as individual literals in the bundle.
		PALETTE: ( () => {
			const colors = require( '@automattic/color-studio' ).colors;
			const stringifiedColors = {};

			// DefinePlugin replaces the values as unescaped text.
			// We therefore need to double-quote each value, to ensure it ends up as a string.
			for ( const color in colors ) {
				stringifiedColors[ color ] = `"${ colors[ color ] }"`;
			}

			return stringifiedColors;
		} )(),
	} );
}

module.exports = definePaletteColorsAsStaticVariables;
