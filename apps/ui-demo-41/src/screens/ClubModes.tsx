import { useEffect, useState } from 'react';
import { demoData } from '../data';
import type { Club, Fixture, Player } from '../types';
import './ClubModes.css';

export type ClubDetailMode = 'transfers' | 'next-match' | 'fixtures' | 'info';
export type ClubSubview =
  | 'general' | 'stats' | 'finances' | 'income' | 'expenditure'
  | 'players-in' | 'players-out' | 'future' | 'loans-in' | 'loans-out' | 'staff-in' | 'staff-out';

interface ClubModesProps {
  club: Club;
  mode: ClubDetailMode;
  onClub: (id: string) => void;
  onPlayer: (id: string) => void;
  show: (label: string) => void;
  subview?: ClubSubview;
  onSubview?: (subview: ClubSubview) => void;
}

const infoViews = [
  ['general', 'General Info'], ['stats', 'Stats'], ['finances', 'Finances'],
  ['income', 'Income'], ['expenditure', 'Expenditure'],
] as const;
const transferViews = [
  ['players-in', 'Players In'], ['players-out', 'Players Out'],
  ['future', 'Future Transfers'], ['loans-in', 'Loans In'],
  ['loans-out', 'Loans Out'], ['staff-in', 'Staff In'], ['staff-out', 'Staff Out'],
] as const;
type InfoView = typeof infoViews[number][0];
type TransferView = typeof transferViews[number][0];

function isInfoView(value: ClubSubview | undefined): value is InfoView {
  return infoViews.some(([id]) => id === value);
}
function isTransferView(value: ClubSubview | undefined): value is TransferView {
  return transferViews.some(([id]) => id === value);
}
function unavailable(show: (label: string) => void, label: string) {
  show(label);
}
function labelFor<T extends readonly (readonly [string, string])[]>(options: T, id: string): string {
  return options.find(([key]) => key === id)?.[1] ?? id;
}
function allPlayers(clubId: string): Player[] {
  return Object.values(demoData.players).filter(player => player.clubId === clubId)
    .sort((a, b) => a.squadNumber - b.squadNumber);
}
function cashAmount(value: string): number {
  const match = /^£([\d.]+)([KM])$/.exec(value);
  if (!match) return 0;
  return Number(match[1]) * (match[2] === 'M' ? 1_000_000 : 1_000);
}
function money(value: number): string {
  return '£' + Math.round(value).toLocaleString('en-GB');
}
function clubSeed(clubId: string): number {
  return [...clubId].reduce((sum, letter) => sum + letter.charCodeAt(0), 0);
}
function formatDate(iso: string): string {
  const [year, month, day] = iso.split('-').map(Number);
  return `${day}.${month}.${String(year).slice(-2)}`;
}

interface TransferRow {
  id: string;
  date: string;
  player: Player;
  otherClub: Club;
  fee: string;
}
function transferRows(club: Club, view: TransferView): TransferRow[] {
  const roster = allPlayers(club.id);
  const otherClubs = Object.values(demoData.clubs).filter(other => other.id !== club.id);
  const incoming = view === 'players-in';
  const source = incoming ? roster.slice(0, 3) : view === 'players-out' ? roster.slice(3, 5) : view === 'loans-out' ? roster.slice(5, 6) : [];
  return source.map((player, index) => ({
    id: `${view}-${player.id}`,
    date: [`28.6.03`, `4.7.03`, `12.7.03`][index],
    player,
    otherClub: otherClubs[(index + (incoming ? 0 : 2)) % otherClubs.length],
    fee: view === 'loans-out' ? 'Loan' : player.value,
  }));
}

function ViewMenu<T extends ClubSubview>({
  label, choices, selected, open, toggle, select,
}: {
  label: string;
  choices: readonly (readonly [T, string])[];
  selected: T;
  open: boolean;
  toggle: () => void;
  select: (id: T) => void;
}) {
  return <div className="uic-view-wrap">
    <button className="uic-tool-button uic-view-trigger" onClick={toggle}
      aria-haspopup="menu" aria-expanded={open}>{label} <span aria-hidden="true">▾</span></button>
    {open && <div className="uic-view-menu" role="menu" aria-label={`${label} choices`}>
      {choices.map(([id, text]) => <button key={id} role="menuitemradio" aria-checked={selected === id}
        onClick={() => select(id)}><span className="uic-check">{selected === id ? '✓' : ''}</span>{text}</button>)}
    </div>}
  </div>;
}

export function ClubModes({ club, mode, onClub, onPlayer, show, subview, onSubview }: ClubModesProps) {
  const [localInfo, setLocalInfo] = useState<InfoView>('general');
  const [localTransfers, setLocalTransfers] = useState<TransferView>('players-in');
  const [openMenu, setOpenMenu] = useState<ClubDetailMode | null>(null);
  useEffect(() => setOpenMenu(null), [club.id, mode]);
  const infoView = isInfoView(subview) ? subview : localInfo;
  const transferView = isTransferView(subview) ? subview : localTransfers;
  function chooseInfo(next: InfoView) {
    setLocalInfo(next);
    onSubview?.(next);
    setOpenMenu(null);
  }
  function chooseTransfer(next: TransferView) {
    setLocalTransfers(next);
    onSubview?.(next);
    setOpenMenu(null);
  }
  const matches = demoData.fixtures.filter(fixture =>
    fixture.homeClubId === club.id || fixture.awayClubId === club.id);
  const nextMatch = matches.find(fixture => fixture.homeScore === undefined);

  return <div className="uic-club-modes" aria-label={`${club.name} ${mode} details`}>
    {mode === 'info' && <>
      <div className="uic-toolbar">
        <ViewMenu label="View" choices={infoViews} selected={infoView}
          open={openMenu === 'info'} toggle={() => setOpenMenu(openMenu === 'info' ? null : 'info')}
          select={chooseInfo} />
      </div>
      <h2 className="uic-section-title">{labelFor(infoViews, infoView)}</h2>
      {infoView === 'general' && <GeneralInfo club={club} />}
      {infoView === 'stats' && <ClubStats club={club} onPlayer={onPlayer} />}
      {infoView === 'finances' && <Finances club={club} />}
      {(infoView === 'income' || infoView === 'expenditure') &&
        <Breakdown club={club} kind={infoView} />}
    </>}
    {mode === 'transfers' && <>
      <div className="uic-toolbar uic-toolbar-split">
        <div className="uic-toolbar-group">
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Previous Season')}>‹‹ Season</button>
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Next Season')}>Season ››</button>
        </div>
        <ViewMenu label="View" choices={transferViews} selected={transferView}
          open={openMenu === 'transfers'} toggle={() => setOpenMenu(openMenu === 'transfers' ? null : 'transfers')}
          select={chooseTransfer} />
      </div>
      <h2 className="uic-section-title">{labelFor(transferViews, transferView)} - Season 2003/4</h2>
      <Transfers club={club} view={transferView} onClub={onClub} onPlayer={onPlayer} />
    </>}
    {mode === 'fixtures' && <>
      <div className="uic-toolbar uic-toolbar-split">
        <div className="uic-toolbar-group">
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Previous Season')}>‹‹ Season</button>
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Next Season')}>Season ››</button>
        </div>
        <div className="uic-toolbar-group">
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Cancel Fixture')}>Cancel</button>
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Arrange Fixture')}>Arrange</button>
        </div>
      </div>
      <h2 className="uic-section-title">Season 2003/4</h2>
      <ClubFixtures club={club} matches={matches} onClub={onClub} />
    </>}
    {mode === 'next-match' && <>
      <div className="uic-toolbar uic-toolbar-split">
        <div className="uic-toolbar-group">
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Previous Date')}>‹‹ Date</button>
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Next Date')}>Date ››</button>
        </div>
        <div className="uic-toolbar-group">
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Progress')}>Progress</button>
          <button className="uic-tool-button" onClick={() => unavailable(show, 'Past Meetings')}>Past Meetings</button>
        </div>
      </div>
      <NextMatch club={club} fixture={nextMatch} onClub={onClub} />
    </>}
  </div>;
}

function GeneralInfo({ club }: { club: Club }) {
  const details = [
    ['Nation', club.nation], ['Status', 'Professional'], ['Finances', 'Secure'],
    ['Stadium', club.stadium], ['Facilities', '12,500 seats'],
    ['Training Ground', 'Club training facilities'],
  ];
  return <div className="uic-panel uic-general">
    <div className="uic-facts">{details.map(([label, value]) =>
      <div className="uic-fact" key={label}><strong>{label}</strong><span>{value}</span></div>)}</div>
    <h3>Non-Playing Staff</h3>
    <div className="uic-staff-row"><strong>{club.manager}</strong><span>Manager</span></div>
    <div className="uic-staff-row"><strong>—</strong><span>Assistant Manager</span></div>
    <div className="uic-staff-row"><strong>—</strong><span>Chief Scout</span></div>
  </div>;
}

function ClubStats({ club, onPlayer }: { club: Club; onPlayer: (id: string) => void }) {
  const roster = allPlayers(club.id);
  const youngest = [...roster].sort((a, b) => a.age - b.age)[0];
  const oldest = [...roster].sort((a, b) => b.age - a.age)[0];
  const highest = [...roster].sort((a, b) => cashAmount(b.value) - cashAmount(a.value))[0];
  const average = roster.length ? (roster.reduce((sum, player) => sum + player.age, 0) / roster.length).toFixed(1) : '—';
  return <div className="uic-panel uic-stats">
    <div className="uic-stat-line"><strong>Players</strong><span>{roster.length}</span></div>
    <div className="uic-stat-line"><strong>Average Age</strong><span>{average}</span></div>
    <div className="uic-stat-line"><strong>Youngest Player</strong>{youngest ? <button onClick={() => onPlayer(youngest.id)}>{youngest.name} ({youngest.age})</button> : <span>—</span>}</div>
    <div className="uic-stat-line"><strong>Oldest Player</strong>{oldest ? <button onClick={() => onPlayer(oldest.id)}>{oldest.name} ({oldest.age})</button> : <span>—</span>}</div>
    <div className="uic-stat-line"><strong>Highest Valued Player</strong>{highest ? <button onClick={() => onPlayer(highest.id)}>{highest.name} ({highest.value})</button> : <span>—</span>}</div>
    <div className="uic-stat-line"><strong>Stadium</strong><span>{club.stadium}</span></div>
  </div>;
}

function financeColumns(club: Club, multiplier: number): number[] {
  const seed = clubSeed(club.id);
  return [0, 1, 2, 3].map(index => (seed % 37 + 34) * (index + 1) * multiplier * 170);
}
const periods = ['This Month', 'Last Month', 'This Year', 'Last Year'];
function FinancialRow({ label, values, tone }: { label: string; values: number[]; tone?: 'positive' | 'negative' }) {
  return <div className={`uic-finance-row ${tone ? `uic-${tone}` : ''}`}>
    <strong>{label}</strong>{values.map((value, index) => <span key={index}>{value < 0 ? `(${money(-value)})` : money(value)}</span>)}
  </div>;
}
function Finances({ club }: { club: Club }) {
  const income = financeColumns(club, 1);
  const outgoings = financeColumns(club, 0.82);
  return <div className="uic-panel uic-finances">
    <div className="uic-finance-head"><strong>Item</strong>{periods.map(period => <span key={period}>{period}</span>)}</div>
    <FinancialRow label="Income" values={income} />
    <FinancialRow label="Expenditure" values={outgoings} />
    <FinancialRow label="Profit/(Loss)" values={income.map((value, index) => value - outgoings[index])} tone="positive" />
    <div className="uic-finance-balance"><strong>Balance</strong><span>{club.balance}</span></div>
    <div className="uic-finance-balance"><strong>Transfer Funds</strong><span>{club.transferBudget}</span></div>
  </div>;
}
function Breakdown({ club, kind }: { club: Club; kind: 'income' | 'expenditure' }) {
  const labels = kind === 'income'
    ? ['Gate Receipts', 'Sponsorship', 'Prize Money', 'Television', 'Players Sold', 'Merchandise', 'Donations', 'Interest', 'Other']
    : ['Wages', 'Bonuses', 'Signing On Fees', 'Dividends', 'Players Bought', 'Ground Maintenance', 'League Fines', 'Interest', 'Other'];
  const base = financeColumns(club, kind === 'income' ? 0.22 : 0.19);
  const weightTotal = labels.reduce((sum, _, index) => sum + index + 1, 0);
  return <div className="uic-panel uic-finances">
    <div className="uic-finance-head"><strong>Item</strong>{periods.map(period => <span key={period}>{period}</span>)}</div>
    {labels.map((label, row) => <FinancialRow key={label} label={label}
      values={base.map(value => Math.round(value * (row + 1) / weightTotal))} />)}
    <FinancialRow label="Total" values={base.map(value => Math.round(value))} tone="positive" />
  </div>;
}

function Transfers({ club, view, onClub, onPlayer }: {
  club: Club; view: TransferView; onClub: (id: string) => void; onPlayer: (id: string) => void;
}) {
  const rows = transferRows(club, view);
  const total = rows.reduce((sum, row) => sum + cashAmount(row.fee), 0);
  return <div className="uic-panel uic-transfer-panel" aria-label={`${labelFor(transferViews, view)} list`}>
    {rows.map(row => <div className="uic-transfer-row" key={row.id}>
      <span className="uic-transfer-date">{row.date}</span>
      <button className="uic-transfer-player" onClick={() => onPlayer(row.player.id)}>{row.player.name}</button>
      <button className="uic-transfer-club" onClick={() => onClub(row.otherClub.id)}>{row.otherClub.shortName}</button>
      <span className="uic-transfer-fee">{row.fee}</span>
    </div>)}
    <div className="uic-transfer-total"><strong className="uic-visually-hidden">Total</strong><span>{money(total)}</span></div>
  </div>;
}

function opponentId(fixture: Fixture, clubId: string): string {
  return fixture.homeClubId === clubId ? fixture.awayClubId : fixture.homeClubId;
}
function ClubFixtures({ club, matches, onClub }: {
  club: Club; matches: readonly Fixture[]; onClub: (id: string) => void;
}) {
  return <div className="uic-panel uic-fixtures-panel">
    {matches.map(fixture => {
      const opponent = demoData.clubs[opponentId(fixture, club.id)];
      const home = fixture.homeClubId === club.id;
      const result = fixture.homeScore === undefined ? '—'
        : `${home ? fixture.homeScore : fixture.awayScore}-${home ? fixture.awayScore : fixture.homeScore}`;
      return <div className="uic-fixture-line" key={fixture.id}>
        <span className="uic-fixture-date">{formatDate(fixture.date)}</span>
        <button onClick={() => onClub(opponent.id)}>{opponent.shortName}</button>
        <span className="uic-fixture-nation">{opponent.nation.slice(0, 3).toUpperCase()}</span>
        <span className="uic-fixture-venue">{home ? 'H' : 'A'}</span>
        <span className="uic-fixture-competition">{demoData.competition.name}</span>
        <span className="uic-fixture-result">{result}</span>
      </div>;
    })}
  </div>;
}

function NextMatch({ club, fixture, onClub }: {
  club: Club; fixture: Fixture | undefined; onClub: (id: string) => void;
}) {
  if (!fixture) return <div className="uic-panel uic-next-match">
    <h2>No upcoming fixture in this synthetic schedule</h2>
  </div>;
  const opponent = demoData.clubs[opponentId(fixture, club.id)];
  const home = fixture.homeClubId === club.id;
  const facts = [
    ['Date', `${formatDate(fixture.date)} EVE`],
    ['Venue', fixture.venue],
    ['Match Rules', 'Group fixture · 90 minutes'],
    ['Last Meeting', 'No earlier meeting in this demo'],
    ['Weather Forecast', 'Dry · 18°C'],
    [`${opponent.shortName} News`, 'No team news recorded'],
  ];
  return <div className="uic-panel uic-next-match">
    <h2><button onClick={() => onClub(opponent.id)}>{opponent.shortName}</button> ({home ? 'Home' : 'Away'})</h2>
    <h3>{demoData.competition.name}</h3>
    <div className="uic-next-facts">{facts.map(([label, value]) =>
      <div key={label}><strong>{label}</strong><span>{value}</span></div>)}</div>
  </div>;
}
