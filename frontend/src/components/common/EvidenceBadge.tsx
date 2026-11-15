import React from 'react';
import { EvidenceClassification } from '../../types/forensics';

interface EvidenceBadgeProps {
  classification: EvidenceClassification;
  confidence?: number;
  className?: string;
}

export const EvidenceBadge: React.FC<EvidenceBadgeProps> = ({
  classification,
  confidence,
  className = '',
}) => {
  const config = {
    OBSERVED: {
      bg: 'bg-emerald-500/10',
      text: 'text-emerald-700',
      border: 'border-emerald-300',
      dot: 'bg-emerald-500',
      label: 'Observed Evidence',
    },
    CORRELATED: {
      bg: 'bg-blue-500/10',
      text: 'text-blue-700',
      border: 'border-blue-300',
      dot: 'bg-blue-500',
      label: 'Correlated Evidence',
    },
    RECONSTRUCTED: {
      bg: 'bg-purple-500/10',
      text: 'text-purple-700',
      border: 'border-purple-300',
      dot: 'bg-purple-500',
      label: 'Reconstructed Artifact',
    },
    SUSPICIOUS: {
      bg: 'bg-rose-500/10',
      text: 'text-rose-700',
      border: 'border-rose-300',
      dot: 'bg-rose-500',
      label: 'Suspicious Anomaly',
    },
    UNKNOWN: {
      bg: 'bg-slate-500/10',
      text: 'text-slate-700',
      border: 'border-slate-300',
      dot: 'bg-slate-400',
      label: 'Unknown / Inconclusive',
    },
  }[classification];

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${config.bg} ${config.text} ${config.border} ${className}`}
      title={`${config.label} - Forensic standard categorization`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
      <span>{classification}</span>
      {confidence !== undefined && (
        <span className="opacity-75 font-mono ml-0.5">({Math.round(confidence)}%)</span>
      )}
    </span>
  );
};

