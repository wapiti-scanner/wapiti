/**
 * @jest-environment jsdom
 */

import { render } from '@testing-library/react';
import SimpleNotice from 'components/notice';
import React from 'react';

describe( 'SimpleNotice', function () {
	const testProps = {
		className: 'test-class',
	};
	describe( 'rendering', function () {
		it( 'can render', () => {
			const { container } = render( <SimpleNotice id="1" status="success" /> );
			expect(
				// eslint-disable-next-line testing-library/no-container, testing-library/no-node-access
				container.getElementsByClassName( 'dops-notice__icon-wrapper' ).length
			).toBeGreaterThan( 0 );
		} );

		it( 'can render with class name passed in', () => {
			const { container } = render( <SimpleNotice { ...testProps }>Toggle Label</SimpleNotice> );
			// eslint-disable-next-line testing-library/no-node-access
			expect( container.firstChild ).toHaveClass( 'test-class' );
		} );
	} );
} );
