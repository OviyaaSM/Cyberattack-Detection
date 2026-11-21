import React from 'react';
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import SeverityBadge from '../components/SeverityBadge';
import RiskGauge from '../components/RiskGauge';
import StatCard from '../components/StatCard';
import Modal from '../components/Modal';

describe('UI Core Components', () => {
  it('renders SeverityBadge correctly for all levels', () => {
    const { unmount } = render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText('CRITICAL')).toBeDefined();
    unmount();

    render(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText('HIGH')).toBeDefined();
  });

  it('renders RiskGauge score accurately', () => {
    render(<RiskGauge score={85.5} />);
    expect(screen.getByText('85.5/100')).toBeDefined();
    expect(screen.getByText('High Risk')).toBeDefined();
  });

  it('renders StatCard title and value', () => {
    render(<StatCard title="Active Alerts" value="7" subtitle="Pending Triage" />);
    expect(screen.getByText('Active Alerts')).toBeDefined();
    expect(screen.getByText('7')).toBeDefined();
    expect(screen.getByText('Pending Triage')).toBeDefined();
  });

  it('controls Modal visibility via isOpen prop', () => {
    const { rerender } = render(
      <Modal isOpen={false} onClose={() => {}} title="Test Modal">
        <p>Modal Body Content</p>
      </Modal>
    );
    expect(screen.queryByText('Modal Body Content')).toBeNull();

    rerender(
      <Modal isOpen={true} onClose={() => {}} title="Test Modal">
        <p>Modal Body Content</p>
      </Modal>
    );
    expect(screen.getByText('Modal Body Content')).toBeDefined();
    expect(screen.getByText('Test Modal')).toBeDefined();
  });
});
