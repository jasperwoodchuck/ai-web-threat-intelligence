import "./App.css";
import { Footer } from "./components/layout/Footer";
import { Header } from "./components/layout/Header";
import { AnimatedSecurityBackground } from "./components/layout/AnimatedSecurityBackground";
import { InvestigationWorkspace } from "./components/investigation/InvestigationWorkspace";
import { InvestigationResults } from "./components/results/InvestigationResults";
import { useInvestigation } from "./hooks/useInvestigation";
import { useTheme } from "./hooks/useTheme";

function App() {
  const { theme, selectTheme } = useTheme();
  const investigation = useInvestigation();

  const hasInvestigationContent = investigation.loading || investigation.error || investigation.availability || investigation.result || investigation.messageResult || investigation.fileResult;

  return <div className={`app-shell${hasInvestigationContent ? " has-investigation-content" : " is-initial"}`}>
    <AnimatedSecurityBackground />
    <Header theme={theme} onThemeChange={selectTheme} />
    <main id="top" className="main-container">
      <InvestigationWorkspace
        mode={investigation.mode}
        onModeChange={investigation.selectMode}
        url={investigation.url}
        onUrlChange={investigation.setUrl}
        message={investigation.message}
        onMessageChange={investigation.setMessage}
        file={investigation.file}
        onFileChange={investigation.setFile}
        fileError={investigation.fileError}
        onFileError={investigation.setFileError}
        loading={investigation.loading}
        onSubmit={investigation.analyze}
      />
      <InvestigationResults
        result={investigation.result}
        availability={investigation.availability}
        fileResult={investigation.fileResult}
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
