import React from 'react';
import { Shield, BookOpen, Cpu, Award } from 'lucide-react';

export const AboutPage: React.FC = () => {
  return (
    <div className="space-y-6 max-w-4xl">
      <div className="bg-white rounded-2xl p-8 border border-slate-200/80 shadow-sm space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-blue-600 flex items-center justify-center text-white shadow-lg shadow-blue-600/30">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-2xl font-black text-slate-900 tracking-tight">ForensiX AI</h2>
            <p className="text-xs text-blue-600 font-bold uppercase tracking-wider">
              AI-Assisted Memory Forensics and Evidence Reconstruction Platform
            </p>
          </div>
        </div>

        <div className="border-t border-slate-100 pt-4 space-y-3">
          <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
            Official Academic Research Title
          </h3>
          <p className="text-sm font-semibold text-slate-900 leading-relaxed bg-slate-50 p-4 rounded-xl border border-slate-200/70">
            Memory Forensics for Volatile Data Analysis via Deep Learning-based Deleted File and Timestamp Reconstruction, Applied to Cloud Service Provider (SaaS/IaaS) Evidence Recovery
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
          <div className="bg-slate-50 p-4 rounded-xl space-y-2">
            <BookOpen className="w-5 h-5 text-blue-600" />
            <h4 className="text-xs font-bold text-slate-900">Academic Objective</h4>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              Advancing DFIR methodology through verifiable deep learning, volatile artifact carving, and multi-source timestamp correlation.
            </p>
          </div>

          <div className="bg-slate-50 p-4 rounded-xl space-y-2">
            <Cpu className="w-5 h-5 text-purple-600" />
            <h4 className="text-xs font-bold text-slate-900">Forensic Integrity</h4>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              Cryptographically verified SHA-256 evidence vaults with strict distinction between observed artifacts and probabilistic reconstructions.
            </p>
          </div>

          <div className="bg-slate-50 p-4 rounded-xl space-y-2">
            <Award className="w-5 h-5 text-emerald-600" />
            <h4 className="text-xs font-bold text-slate-900">Lead Investigator</h4>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              A. Abhiram — Final Year Digital Forensics Research Project.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

