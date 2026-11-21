import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import Sidebar from '../components/Sidebar';
import Navbar from '../components/Navbar';

describe('Navigation and Shell Components', () => {
  it('renders all 8 primary navigation items in Sidebar', () => {
    render(
      <BrowserRouter>
        <Sidebar />
      </BrowserRouter>
    );

    expect(screen.getByText('Overview')).toBeDefined();
    expect(screen.getByText('Live Monitor')).toBeDefined();
    expect(screen.getByText('Attack Detection')).toBeDefined();
    expect(screen.getByText('Temporal Timeline')).toBeDefined();
    expect(screen.getByText('Network Graph')).toBeDefined();
    expect(screen.getByText('Simulation Lab')).toBeDefined();
    expect(screen.getByText('Investigation Center')).toBeDefined();
    expect(screen.getByText('Reports & Config')).toBeDefined();
  });

  it('renders brand title and action triggers in Navbar', () => {
    render(
      <BrowserRouter>
        <Navbar systemHealth="NORMAL" />
      </BrowserRouter>
    );

    expect(screen.getByText('TEMPORAL-SOC')).toBeDefined();
    expect(screen.getByText('Run Detection')).toBeDefined();
    expect(screen.getByText('Reset State')).toBeDefined();
    expect(screen.getByText('NORMAL')).toBeDefined();
  });
});
