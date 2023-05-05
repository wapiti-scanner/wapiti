/**
 * @jest-environment jsdom
 */

import { render, screen } from '@testing-library/react';
import Button from 'components/button';
import React from 'react';

describe( 'Button', function () {
	const testProps = {
		className: 'test-class',
	};
	it( 'can render', () => {
		render( <Button /> );
		expect( screen.getByRole( 'button' ) ).toBeInTheDocument();
	} );
	it( 'can render compact button', () => {
		render( <Button compact={ true } /> );
		expect( screen.getByRole( 'button' ) ).toHaveClass( 'is-compact' );
	} );
	it( 'can render with class name passed in', () => {
		render( <Button { ...testProps } /> );
		expect( screen.getByRole( 'button' ) ).toHaveClass( 'test-class' );
	} );
} );
