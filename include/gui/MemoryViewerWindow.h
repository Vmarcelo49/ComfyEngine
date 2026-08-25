#pragma once

#include <QMainWindow>
#include <cstdint>
#include <unordered_map>
#include <vector>

class QLineEdit;
class QTableWidget;
class QLabel;
class QSpinBox;
class QCheckBox;
class QTimer;
class QDockWidget;
class QToolButton;
class QTreeWidget;
class QShowEvent;

namespace core {
class TargetProcess;
class CodeInjector;
}

class MemoryViewerWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MemoryViewerWindow(QWidget *parent = nullptr);

    void setTarget(core::TargetProcess *proc, uintptr_t address, core::CodeInjector *injector = nullptr);

protected:
    void showEvent(QShowEvent *event) override;

private slots:
    void onGo();
    void onPrevPage();
    void onNextPage();
    void onCellDoubleClicked(int row, int column);
    void onRegionDoubleClicked(int row, int column);
    void onHexContextMenu(const QPoint &pos);
    void onDisasmContextMenu(const QPoint &pos);
    void onRegionContextMenu(const QPoint &pos);

private:
    void setupUi();
    void refreshView();
    void refreshRegions();
    void selectRegionFor(uintptr_t address);
    void jumpTo(uintptr_t address);
    void setAutoRefresh(bool enabled);
    uintptr_t currentSelectionAddress() const;
    void updateSelectionAddress(uintptr_t address);
    std::vector<uint8_t> readBytes(uintptr_t address, size_t length) const;
    bool ensurePatchBackup(uintptr_t address, size_t length);
    void restorePatchedBytes(uintptr_t address);
    void triggerAutoAssembler();
    void triggerAobInjection();
    void triggerPointerScanner();
    void applyStyle();

    core::TargetProcess *proc_{};
    core::CodeInjector *injector_{};
    uintptr_t baseAddress_{0};
    size_t bytesPerRow_{16};
    size_t rows_{256}; // default 4096 bytes per page
    uintptr_t lastSelectedAddress_{0};

    QLineEdit *addrEdit_{};
    QLabel *regionLabel_{};
    QCheckBox *autoRefreshCheck_{};
    QSpinBox *refreshIntervalSpin_{};
    QTimer *refreshTimer_{};
    QSpinBox *bytesPerPageSpin_{};
    QCheckBox *execOnlyCheck_{};
    QTableWidget *regionTable_{};
    QTableWidget *disasmTable_{};
    QTableWidget *hexTable_{};
    QDockWidget *regionDock_{};
    QDockWidget *cheatDock_{};
    QTreeWidget *cheatList_{};
    QLineEdit *cheatDescEdit_{};

    void copyToClipboard(const QString &text);
    void patchBytes(uintptr_t address, const QString &defaultBytes);

    std::unordered_map<uintptr_t, std::vector<uint8_t>> patchBackups_;
    bool lastReadFailed_{false};
    uintptr_t deferredAddress_{0};
    bool deferredRefresh_{false};
};
