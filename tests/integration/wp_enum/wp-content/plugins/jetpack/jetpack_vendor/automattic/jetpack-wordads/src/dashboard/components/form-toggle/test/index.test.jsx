/**
 * @jest-environment jsdom
 */

import { render, screen } from '@testing-library/react';
import CompactFormToggle from 'components/form-toggle/compact';
import React from 'react';

describe( 'CompactFormToggle', function () {
	const testProps = {
		className: 'test-class',
	};
	describe( 'rendering', function () {
		it( 'can render', () => {
			render( <CompactFormToggle>Toggle Label</CompactFormToggle> );
			expect( screen.getByText( 'Toggle Label' ) ).toBeInTheDocument();
			expect( screen.getAllByRole( 'checkbox' )[ 0 ] ).toHaveClass( 'is-compact' );
		} );

		it( 'can render with class name passed in', () => {
			render( <CompactFormToggle { ...testProps }>Toggle Label</CompactFormToggle> );
			expect( screen.getAllByRole( 'checkbox' )[ 0 ] ).toHaveClass( 'test-class' );
		} );
	} );
} );
