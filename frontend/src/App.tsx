import "./App.css";
import { Footer } from "./components/layout/Footer";
import { Header } from "./components/layout/Header";
import { InvestigationWorkspace } from "./components/investigation/InvestigationWorkspace";
import { InvestigationResults } from "./components/results/InvestigationResults";
import { useInvestigation } from "./hooks/useInvestigation";
import { useTheme } from "./hooks/useTheme";

function App() {
  const { theme, selectTheme } = useTheme();
  const investigation = useInvestigation();

  return <div className="app-shell">
    <Header theme={theme} onThemeChange={selectTheme} />
    <main id="top" className="main-container">
      <InvestigationWorkspace
        mode={investigation.mode}
        onModeChange={investigation.selectMode}
        url={investigation.url}
        onUrlChange={investigation.setUrl}
        message={investigation.message}
        onMessageChange={investigation.setMessage}
        loading={investigation.loading}
        onSubmit={investigation.analyze}
      />
      <InvestigationResults
        result={investigation.result}
        messageResult={investigation.messageResult}
        error={investigation.error}
        loading={investigation.loading}
        detailedOpen={investigation.detailedOpen}
        setDetailedOpen={investigation.setDetailedOpen}
        riskEvidenceOpen={investigation.riskEvidenceOpen}
        setRiskEvidenceOpen={investigation.setRiskEvidenceOpen}
      />
    </main>
    <Footer />
  </div>;
}

export default App;
