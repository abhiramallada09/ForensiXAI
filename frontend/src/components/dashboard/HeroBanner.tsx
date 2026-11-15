import React from 'react';
import { Play } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const HeroBanner: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0C1938] via-[#0D214C] to-[#0A1A3A] border border-[#1B2F63] p-7 text-white shadow-xl">
      {/* Background Cyber Mesh / Glow */}
      <div className="absolute top-0 right-0 w-96 h-full bg-blue-500/10 blur-3xl pointer-events-none" />
      <div className="absolute -bottom-10 right-28 w-64 h-64 bg-cyan-500/10 blur-2xl pointer-events-none" />

      <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        {/* Left Column: Text & CTA */}
        <div className="max-w-2xl">
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white mb-2">
            Memory Forensics for Volatile Data Analysis
          </h2>
          <p className="text-sm sm:text-base text-cyan-200/90 font-medium mb-6">
            Analyze. Reconstruct. Detect. – Powered by Deep Learning.
          </p>
          <button
            onClick={() => navigate('/cases/new')}
            className="inline-flex items-center gap-2.5 px-5 py-2.5 bg-[#1E50FF] hover:bg-blue-600 active:scale-[0.98] transition-all text-white font-semibold text-xs rounded-xl shadow-lg shadow-blue-600/40"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Start New Investigation</span>
          </button>
        </div>

        {/* Right Column: Cyber Forensic Terminal/Laptop Graphic */}
        <div className="hidden md:flex items-center justify-center shrink-0">
          <div className="relative w-64 h-36 flex items-center justify-center">
            {/* Holographic glowing laptop with fingerprint screen */}
            <svg className="w-full h-full text-blue-400" viewBox="0 0 240 140" fill="none">
              {/* Cloud connection on top right */}
              <path
                d="M190 28C190 22 195 18 201 18C206 18 210 21 211 25C215 25 218 28 218 32C218 36 215 39 211 39H191C187 39 184 36 184 32C184 28 187 25 190 28Z"
                stroke="#00D2FF"
                strokeWidth="2"
                fill="#0E2757"
              />
              <path d="M195 40L160 65" stroke="#00D2FF" strokeWidth="1" strokeDasharray="3 3" opacity="0.6" />

              {/* Laptop Screen Body */}
              <rect x="50" y="20" width="130" height="85" rx="6" fill="#07122C" stroke="#2B6BFF" strokeWidth="2" />
              {/* Inner screen */}
              <rect x="56" y="26" width="118" height="73" rx="3" fill="#040A1A" />

              {/* Fingerprint on Screen */}
              <ellipse cx="115" cy="62" rx="14" ry="18" stroke="#00F0FF" strokeWidth="1.5" strokeDasharray="3 2" />
              <ellipse cx="115" cy="62" rx="9" ry="12" stroke="#52A5FF" strokeWidth="1.5" />
              <ellipse cx="115" cy="62" rx="4" ry="6" stroke="#90C8FF" strokeWidth="1.5" />

              {/* Laptop Base */}
              <path d="M25 105L45 105L50 115L180 115L185 105L205 105C209 105 212 108 210 112L200 120H30L20 112C18 108 21 105 25 105Z" fill="#142A5C" stroke="#2B6BFF" strokeWidth="1.5" />
              <rect x="95" y="107" width="40" height="3" rx="1.5" fill="#3B82F6" />
            </svg>
          </div>
        </div>
      </div>
    </div>
  );
};

