import React from 'react';
import { AlertTriangle, Info } from 'lucide-react';

export const DisclaimerBanner: React.FC = () => {
  return (
    <div className="bg-amber-500/10 border-b border-amber-300/40 px-4 py-2 text-xs text-amber-900 flex items-center justify-between">
      <div className="flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0" />
        <span className="font-medium">
          <strong className="font-semibold">Controlled Research Prototype:</strong> This platform assists digital forensic analysis. Reconstruction results are probabilistic unless directly supported by evidence. AI findings require manual investigator verification.
        </span>
      </div>
      <div className="hidden md:flex items-center gap-1.5 text-amber-700 text-[11px] font-mono">
        <Info className="w-3.5 h-3.5" />
        <span>Evidence Integrity Rule: Never Execute Ingested Artifacts</span>
      </div>
    </div>
  );
};

