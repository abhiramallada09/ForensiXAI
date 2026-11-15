import React, { createContext, useContext, useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Case } from '../types/forensics';
import { fetchCases } from '../api/client';

interface CaseContextType {
  activeCaseId: string | null;
  activeCase: Case | null;
  setActiveCaseId: (id: string | null) => void;
  setActiveCase: (caseObj: Case | null) => void;
  allCases: Case[];
  isLoadingCases: boolean;
}

const CaseContext = createContext<CaseContextType | undefined>(undefined);

const STORAGE_KEY = 'forensix_active_case_id';

export const CaseProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeCaseId, setActiveCaseIdState] = useState<string | null>(() => {
    return localStorage.getItem(STORAGE_KEY) || null;
  });

  const { data: allCases = [], isLoading: isLoadingCases } = useQuery({
    queryKey: ['cases'],
    queryFn: () => fetchCases(),
  });

  const [activeCase, setActiveCaseState] = useState<Case | null>(null);

  // Sync activeCase object when allCases or activeCaseId changes
  useEffect(() => {
    if (activeCaseId && allCases.length > 0) {
      const found = allCases.find((c) => c.id === activeCaseId);
      if (found) {
        setActiveCaseState(found);
      } else {
        // Fallback to first available case if previously stored ID doesn't exist
        setActiveCaseState(allCases[0]);
        setActiveCaseIdState(allCases[0].id);
        localStorage.setItem(STORAGE_KEY, allCases[0].id);
      }
    } else if (!activeCaseId && allCases.length > 0) {
      // Default to the most recent case
      setActiveCaseState(allCases[0]);
      setActiveCaseIdState(allCases[0].id);
      localStorage.setItem(STORAGE_KEY, allCases[0].id);
    }
  }, [activeCaseId, allCases]);

  const setActiveCaseId = (id: string | null) => {
    setActiveCaseIdState(id);
    if (id) {
      localStorage.setItem(STORAGE_KEY, id);
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  };

  const setActiveCase = (caseObj: Case | null) => {
    setActiveCaseState(caseObj);
    if (caseObj) {
      setActiveCaseId(caseObj.id);
    } else {
      setActiveCaseId(null);
    }
  };

  return (
    <CaseContext.Provider
      value={{
        activeCaseId,
        activeCase,
        setActiveCaseId,
        setActiveCase,
        allCases,
        isLoadingCases,
      }}
    >
      {children}
    </CaseContext.Provider>
  );
};

export const useCase = () => {
  const context = useContext(CaseContext);
  if (!context) {
    throw new Error('useCase must be used within a CaseProvider');
  }
  return context;
};

